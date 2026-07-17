use super::percent;
use log::{info, warn};
use std::fs;
use std::mem;
use std::path::Path;
use std::time::{Duration, Instant};

const PROC_STAT: &str = "/proc/stat";
const PROC_SELF_CGROUP: &str = "/proc/self/cgroup";
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const CGROUP_V1_CPU_ROOTS: [&str; 3] = [
    "/sys/fs/cgroup/cpu",
    "/sys/fs/cgroup/cpu,cpuacct",
    "/sys/fs/cgroup/cpuacct,cpu",
];
const CPU_CAPACITY_REFRESH: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy)]
struct HostCpuCounters {
    total_ticks: u64,
    idle_ticks: u64,
}

#[derive(Debug, Clone, Copy)]
struct ProcessCpuCounters {
    sampled_at: Instant,
    process_cpu_ns: u64,
}

pub(super) struct CpuUtilization {
    pub host_percent: Option<f64>,
    pub process_percent: Option<f64>,
}

pub(super) struct CpuSampler {
    previous_host: Option<HostCpuCounters>,
    previous_process: Option<ProcessCpuCounters>,
    process_capacity_cores: f64,
    last_capacity_refresh: Instant,
    host_error_reported: bool,
    process_error_reported: bool,
}

impl CpuSampler {
    pub(super) fn new() -> Self {
        let process_capacity_cores = detect_process_cpu_capacity_cores();
        info!(
            "CPU resource capacity: host=true process_cores={:.2}",
            process_capacity_cores
        );

        Self {
            previous_host: None,
            previous_process: None,
            process_capacity_cores,
            last_capacity_refresh: Instant::now(),
            host_error_reported: false,
            process_error_reported: false,
        }
    }

    pub(super) fn sample(&mut self) -> CpuUtilization {
        let sampled_at = Instant::now();
        self.refresh_process_capacity(sampled_at);
        CpuUtilization {
            host_percent: self.sample_host(),
            process_percent: self.sample_process(sampled_at),
        }
    }

    fn refresh_process_capacity(&mut self, sampled_at: Instant) {
        if sampled_at.duration_since(self.last_capacity_refresh) < CPU_CAPACITY_REFRESH {
            return;
        }

        let current = detect_process_cpu_capacity_cores();
        if current != self.process_capacity_cores {
            info!(
                "Process CPU resource capacity changed: cores={:.2}->{:.2}",
                self.process_capacity_cores, current
            );
            self.process_capacity_cores = current;
            self.previous_process = None;
        }
        self.last_capacity_refresh = sampled_at;
    }

    fn sample_host(&mut self) -> Option<f64> {
        let current = match read_host_cpu_counters() {
            Ok(current) => current,
            Err(error) => {
                if !self.host_error_reported {
                    warn!(
                        "Unable to sample host CPU utilization: {}; suppressing repeated warnings",
                        error
                    );
                    self.host_error_reported = true;
                }
                self.previous_host = None;
                return None;
            }
        };

        if self.host_error_reported {
            info!("Host CPU utilization sampling recovered");
            self.host_error_reported = false;
        }

        let utilization = self
            .previous_host
            .map(|previous| host_cpu_utilization_percent(previous, current));
        self.previous_host = Some(current);
        utilization
    }

    fn sample_process(&mut self, sampled_at: Instant) -> Option<f64> {
        let current = match process_cpu_time_ns() {
            Ok(process_cpu_ns) => ProcessCpuCounters {
                sampled_at,
                process_cpu_ns,
            },
            Err(error) => {
                if !self.process_error_reported {
                    warn!(
                        "Unable to sample XLB process CPU utilization: {}; suppressing repeated warnings",
                        error
                    );
                    self.process_error_reported = true;
                }
                self.previous_process = None;
                return None;
            }
        };

        if self.process_error_reported {
            info!("XLB process CPU utilization sampling recovered");
            self.process_error_reported = false;
        }

        let utilization = self.previous_process.and_then(|previous| {
            let elapsed_ns = elapsed_ns(previous.sampled_at, current.sampled_at);
            (elapsed_ns > 0).then(|| {
                process_cpu_utilization_percent(
                    current
                        .process_cpu_ns
                        .saturating_sub(previous.process_cpu_ns),
                    elapsed_ns,
                    self.process_capacity_cores,
                )
            })
        });

        self.previous_process = Some(current);
        utilization
    }
}

fn read_host_cpu_counters() -> std::io::Result<HostCpuCounters> {
    let stat = fs::read_to_string(PROC_STAT)?;
    let aggregate = stat
        .lines()
        .find(|line| line.starts_with("cpu "))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "aggregate CPU line is missing from /proc/stat",
            )
        })?;

    parse_host_cpu_counters(aggregate).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "aggregate CPU counters are invalid",
        )
    })
}

fn parse_host_cpu_counters(value: &str) -> Option<HostCpuCounters> {
    let mut fields = value.split_whitespace();
    if fields.next()? != "cpu" {
        return None;
    }

    let mut counters = [0u64; 8];
    for counter in &mut counters {
        *counter = fields.next().unwrap_or("0").parse().ok()?;
    }

    let total_ticks = counters
        .iter()
        .fold(0u64, |total, value| total.saturating_add(*value));
    let idle_ticks = counters[3].saturating_add(counters[4]);
    Some(HostCpuCounters {
        total_ticks,
        idle_ticks,
    })
}

fn host_cpu_utilization_percent(previous: HostCpuCounters, current: HostCpuCounters) -> f64 {
    let total_delta = current.total_ticks.saturating_sub(previous.total_ticks);
    let idle_delta = current
        .idle_ticks
        .saturating_sub(previous.idle_ticks)
        .min(total_delta);
    percent(
        total_delta.saturating_sub(idle_delta) as f64,
        total_delta as f64,
    )
}

fn process_cpu_time_ns() -> std::io::Result<u64> {
    let mut timestamp = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let result = unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut timestamp) };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok((timestamp.tv_sec as u64 * 1_000_000_000) + timestamp.tv_nsec as u64)
}

fn process_cpu_utilization_percent(cpu_delta_ns: u64, elapsed_ns: u64, capacity_cores: f64) -> f64 {
    if elapsed_ns == 0 || capacity_cores <= 0.0 {
        return 0.0;
    }

    percent(cpu_delta_ns as f64, elapsed_ns as f64 * capacity_cores)
}

fn detect_process_cpu_capacity_cores() -> f64 {
    let affinity_capacity = scheduler_affinity_capacity_cores().unwrap_or(1.0);
    let environment_limit = std::env::var("XLB_CPU_LIMIT_MILLICORES")
        .ok()
        .and_then(|value| parse_cpu_limit_millicores(&value));

    select_process_cpu_capacity(
        affinity_capacity,
        environment_limit,
        [
            effective_cgroup_v2_cpu_quota(),
            effective_cgroup_v1_cpu_quota(),
        ],
    )
}

fn scheduler_affinity_capacity_cores() -> Option<f64> {
    // SAFETY: An all-zero bitset is a valid empty cpu_set_t.
    let mut affinity = unsafe { mem::zeroed::<libc::cpu_set_t>() };
    // SAFETY: affinity points to writable storage of the exact size passed to
    // sched_getaffinity, and remains alive for the duration of the call.
    let result = unsafe {
        libc::sched_getaffinity(
            0,
            mem::size_of::<libc::cpu_set_t>(),
            std::ptr::addr_of_mut!(affinity),
        )
    };
    if result != 0 {
        return None;
    }

    // SAFETY: sched_getaffinity successfully initialized the complete bitset.
    let count = unsafe { libc::CPU_COUNT(&affinity) };
    (count > 0).then_some(f64::from(count))
}

fn select_process_cpu_capacity(
    affinity_capacity: f64,
    environment_limit: Option<f64>,
    cgroup_limits: [Option<f64>; 2],
) -> f64 {
    // Cgroup files reflect live in-place resource resizing. The Downward API
    // environment value is fixed at process start, so it is only a fallback
    // when the runtime does not expose a readable cgroup quota.
    let effective_limit = cgroup_limits
        .into_iter()
        .flatten()
        .reduce(f64::min)
        .or(environment_limit);

    effective_limit.map_or(affinity_capacity, |limit| affinity_capacity.min(limit))
}

fn parse_cpu_limit_millicores(value: &str) -> Option<f64> {
    let millicores = value.trim().parse::<f64>().ok()?;
    (millicores.is_finite() && millicores > 0.0).then_some(millicores / 1_000.0)
}

fn effective_cgroup_v2_cpu_quota() -> Option<f64> {
    let cgroups = fs::read_to_string(PROC_SELF_CGROUP).ok()?;
    let relative = cgroups
        .lines()
        .find_map(|line| line.strip_prefix("0::"))?
        .trim_start_matches('/');
    let root = Path::new(CGROUP_ROOT);
    let mut current = root.join(relative);
    if !current.starts_with(root) || !current.is_dir() {
        current = root.to_path_buf();
    }

    let mut effective: Option<f64> = None;
    loop {
        if let Ok(value) = fs::read_to_string(current.join("cpu.max"))
            && let Some(quota) = parse_cpu_max(&value)
        {
            effective = Some(effective.map_or(quota, |limit| limit.min(quota)));
        }

        if current == root || !current.pop() || !current.starts_with(root) {
            break;
        }
    }

    effective
}

fn parse_cpu_max(value: &str) -> Option<f64> {
    let mut fields = value.split_whitespace();
    let quota = fields.next()?;
    let period = fields.next()?.parse::<f64>().ok()?;
    if quota == "max" || period <= 0.0 {
        return None;
    }

    let quota = quota.parse::<f64>().ok()?;
    (quota.is_finite() && quota > 0.0).then_some(quota / period)
}

fn effective_cgroup_v1_cpu_quota() -> Option<f64> {
    let cgroups = fs::read_to_string(PROC_SELF_CGROUP).ok()?;
    let relative = parse_cgroup_v1_cpu_path(&cgroups)?;
    let root = CGROUP_V1_CPU_ROOTS
        .iter()
        .map(Path::new)
        .find(|root| root.is_dir())?;
    let mut current = root.join(relative.trim_start_matches('/'));
    if !current.starts_with(root) || !current.is_dir() {
        current = root.to_path_buf();
    }

    let mut effective: Option<f64> = None;
    loop {
        let quota = fs::read_to_string(current.join("cpu.cfs_quota_us"));
        let period = fs::read_to_string(current.join("cpu.cfs_period_us"));
        if let (Ok(quota), Ok(period)) = (quota, period)
            && let Some(quota) = parse_cgroup_v1_cpu_quota(&quota, &period)
        {
            effective = Some(effective.map_or(quota, |limit| limit.min(quota)));
        }

        if current == root || !current.pop() || !current.starts_with(root) {
            break;
        }
    }

    effective
}

fn parse_cgroup_v1_cpu_path(value: &str) -> Option<&str> {
    value.lines().find_map(|line| {
        let mut fields = line.splitn(3, ':');
        fields.next()?;
        let controllers = fields.next()?;
        let path = fields.next()?;
        controllers
            .split(',')
            .any(|controller| controller == "cpu")
            .then_some(path)
    })
}

fn parse_cgroup_v1_cpu_quota(quota: &str, period: &str) -> Option<f64> {
    let quota = quota.trim().parse::<f64>().ok()?;
    let period = period.trim().parse::<f64>().ok()?;
    (quota.is_finite() && quota > 0.0 && period.is_finite() && period > 0.0)
        .then_some(quota / period)
}

fn elapsed_ns(previous: Instant, current: Instant) -> u64 {
    u64::try_from(current.saturating_duration_since(previous).as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_aggregate_host_cpu_counters() {
        let counters = parse_host_cpu_counters("cpu  100 10 20 200 30 5 15 20 0 0")
            .expect("valid aggregate counters");

        assert_eq!(counters.total_ticks, 400);
        assert_eq!(counters.idle_ticks, 230);
        assert!(parse_host_cpu_counters("cpu0 100 10 20 200").is_none());
    }

    #[test]
    fn calculates_host_cpu_busy_percentage() {
        let previous = HostCpuCounters {
            total_ticks: 1_000,
            idle_ticks: 400,
        };
        let current = HostCpuCounters {
            total_ticks: 1_200,
            idle_ticks: 450,
        };

        assert_eq!(host_cpu_utilization_percent(previous, current), 75.0);
    }

    #[test]
    fn normalizes_process_cpu_against_its_capacity() {
        assert_eq!(
            process_cpu_utilization_percent(1_000_000_000, 1_000_000_000, 4.0),
            25.0
        );
        assert_eq!(parse_cpu_limit_millicores("2500"), Some(2.5));
        assert_eq!(parse_cpu_max("250000 100000"), Some(2.5));
        assert_eq!(parse_cpu_max("max 100000"), None);
    }

    #[test]
    fn selects_exact_fractional_and_strictest_cpu_capacity() {
        assert_eq!(
            select_process_cpu_capacity(64.0, Some(8.0), [Some(2.5), Some(4.0)]),
            2.5
        );
        assert_eq!(
            select_process_cpu_capacity(64.0, Some(8.0), [Some(4.0), Some(1.5)]),
            1.5
        );
        assert_eq!(
            select_process_cpu_capacity(2.0, None, [Some(2.5), Some(4.0)]),
            2.0
        );
    }

    #[test]
    fn live_cgroup_capacity_overrides_stale_environment_limit() {
        assert_eq!(
            select_process_cpu_capacity(64.0, Some(2.0), [Some(4.0), None]),
            4.0
        );
        assert_eq!(
            select_process_cpu_capacity(64.0, Some(2.0), [None, None]),
            2.0
        );
    }

    #[test]
    fn parses_cgroup_v1_cpu_capacity() {
        let cgroups = "11:memory:/workload\n10:cpu,cpuacct:/workload/container\n";

        assert_eq!(
            parse_cgroup_v1_cpu_path(cgroups),
            Some("/workload/container")
        );
        assert_eq!(parse_cgroup_v1_cpu_quota("250000\n", "100000\n"), Some(2.5));
        assert_eq!(parse_cgroup_v1_cpu_quota("-1\n", "100000\n"), None);
    }
}
