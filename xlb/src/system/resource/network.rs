use super::percent;
use log::{info, warn};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const PROC_NET_DEV: &str = "/proc/net/dev";
const LINK_SPEED_REFRESH: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy)]
struct NetworkCounters {
    sampled_at: Instant,
    rx_bytes: u64,
    tx_bytes: u64,
}

struct NetworkInterfaceSampler {
    name: String,
    path: PathBuf,
    link_speed_bps: Option<f64>,
    capacity_is_configured: bool,
    previous: Option<NetworkCounters>,
    capacity_error_reported: bool,
    counter_error_reported: bool,
}

impl NetworkInterfaceSampler {
    fn new(name: String, configured_capacity_mbps: Option<u64>) -> Self {
        let path = Path::new("/sys/class/net").join(&name);
        let configured_link_speed_bps =
            configured_capacity_mbps.map(|capacity_mbps| capacity_mbps as f64 * 1_000_000.0);
        let link_speed_bps =
            configured_link_speed_bps.or_else(|| read_link_speed_bps(&path.join("speed")));

        if let Some(link_speed_bps) = link_speed_bps {
            info!(
                "Network resource capacity: interface={} capacity_mbps={:.0} source={}",
                name,
                link_speed_bps / 1_000_000.0,
                if configured_link_speed_bps.is_some() {
                    "configured"
                } else {
                    "driver"
                }
            );
        } else {
            warn!(
                "XDP interface {} did not report a usable link speed; xlb.resource.utilization will not be exported",
                name
            );
        }

        Self {
            name,
            path,
            link_speed_bps,
            capacity_is_configured: configured_link_speed_bps.is_some(),
            previous: None,
            capacity_error_reported: link_speed_bps.is_none(),
            counter_error_reported: false,
        }
    }

    fn sample(&mut self, sampled_at: Instant, counters: Option<(u64, u64)>) -> Option<f64> {
        let link_speed_bps = self.link_speed_bps?;
        let Some((rx_bytes, tx_bytes)) = counters else {
            if !self.counter_error_reported {
                warn!(
                    "Interface {} is missing from /proc/net/dev; suppressing repeated warnings",
                    self.name
                );
                self.counter_error_reported = true;
            }
            self.previous = None;
            return None;
        };
        let current = NetworkCounters {
            sampled_at,
            rx_bytes,
            tx_bytes,
        };

        let had_previous = self.previous.is_some();
        let utilization = self.previous.and_then(|previous| {
            network_utilization_from_samples(previous, current, link_speed_bps)
        });

        if utilization.is_some() && self.counter_error_reported {
            info!(
                "Network utilization sampling recovered for interface {}",
                self.name
            );
            self.counter_error_reported = false;
        } else if utilization.is_none() && had_previous && !self.counter_error_reported {
            warn!(
                "Network counters reset or had an invalid interval for interface {}; suppressing utilization until the next complete sample",
                self.name
            );
            self.counter_error_reported = true;
        }

        self.previous = Some(current);
        utilization
    }

    fn refresh_link_speed(&mut self) {
        if self.capacity_is_configured {
            return;
        }

        let speed_path = self.path.join("speed");
        let Some(current) = read_link_speed_bps(&speed_path) else {
            if !self.capacity_error_reported {
                warn!(
                    "XDP interface {} no longer reports a usable link speed; suppressing repeated warnings",
                    self.name
                );
                self.capacity_error_reported = true;
            }
            self.link_speed_bps = None;
            self.previous = None;
            return;
        };

        match self.link_speed_bps {
            Some(previous) if previous != current => {
                info!(
                    "Network resource capacity changed: interface={} link_speed_mbps={:.0}->{:.0}",
                    self.name,
                    previous / 1_000_000.0,
                    current / 1_000_000.0
                );
                self.previous = None;
            }
            None if self.capacity_error_reported => info!(
                "Network resource capacity detected: interface={} link_speed_mbps={:.0}",
                self.name,
                current / 1_000_000.0
            ),
            _ => {}
        }

        self.capacity_error_reported = false;
        self.link_speed_bps = Some(current);
    }
}

pub(super) struct NetworkSampler {
    interfaces: Vec<NetworkInterfaceSampler>,
    snapshot_error_reported: bool,
    last_link_speed_refresh: Instant,
}

impl NetworkSampler {
    pub(super) fn new(mut interfaces: Vec<String>, configured_capacity_mbps: Option<u64>) -> Self {
        interfaces.sort_unstable();
        interfaces.dedup();

        if interfaces.is_empty() {
            warn!(
                "No XDP interfaces are available for resource sampling; xlb.resource.utilization will not be exported"
            );
        } else {
            info!(
                "Network resource sampling enabled for {} XDP interface(s)",
                interfaces.len()
            );
        }

        Self {
            interfaces: interfaces
                .into_iter()
                .map(|interface| NetworkInterfaceSampler::new(interface, configured_capacity_mbps))
                .collect(),
            snapshot_error_reported: false,
            last_link_speed_refresh: Instant::now(),
        }
    }

    pub(super) fn sample(&mut self) -> Option<f64> {
        if self.interfaces.is_empty() {
            return None;
        }

        let sampled_at = Instant::now();
        if sampled_at.duration_since(self.last_link_speed_refresh) >= LINK_SPEED_REFRESH {
            for interface in &mut self.interfaces {
                interface.refresh_link_speed();
            }
            self.last_link_speed_refresh = sampled_at;
        }

        // Read one host-wide snapshot per tick. Reading each interface's sysfs
        // counters separately scales poorly on hosts with many XDP attachments.
        let counters = match read_network_device_counters() {
            Ok(counters) => counters,
            Err(error) => {
                if !self.snapshot_error_reported {
                    warn!(
                        "Unable to sample interface counters from /proc/net/dev: {}; suppressing repeated warnings",
                        error
                    );
                    self.snapshot_error_reported = true;
                }
                for interface in &mut self.interfaces {
                    interface.previous = None;
                }
                return None;
            }
        };

        if self.snapshot_error_reported {
            info!("Interface counter sampling recovered");
            self.snapshot_error_reported = false;
        }

        complete_max(
            self.interfaces.iter_mut().map(|interface| {
                interface.sample(sampled_at, counters.get(&interface.name).copied())
            }),
        )
    }
}

fn read_network_device_counters() -> std::io::Result<HashMap<String, (u64, u64)>> {
    let devices = fs::read_to_string(PROC_NET_DEV)?;
    Ok(parse_network_device_counters(&devices))
}

fn parse_network_device_counters(value: &str) -> HashMap<String, (u64, u64)> {
    value
        .lines()
        .filter_map(|line| {
            let (name, counters) = line.split_once(':')?;
            let mut counters = counters.split_whitespace();
            let rx_bytes = counters.next()?.parse::<u64>().ok()?;
            let tx_bytes = counters.nth(7)?.parse::<u64>().ok()?;
            Some((name.trim().to_string(), (rx_bytes, tx_bytes)))
        })
        .collect()
}

fn read_link_speed_bps(path: &Path) -> Option<f64> {
    let speed_mbps = fs::read_to_string(path).ok()?.trim().parse::<f64>().ok()?;
    (speed_mbps.is_finite() && speed_mbps > 0.0).then_some(speed_mbps * 1_000_000.0)
}

fn network_utilization_from_samples(
    previous: NetworkCounters,
    current: NetworkCounters,
    link_speed_bps: f64,
) -> Option<f64> {
    let elapsed_ns = elapsed_ns(previous.sampled_at, current.sampled_at);
    let rx_delta_bytes = current.rx_bytes.checked_sub(previous.rx_bytes)?;
    let tx_delta_bytes = current.tx_bytes.checked_sub(previous.tx_bytes)?;
    (elapsed_ns > 0).then(|| {
        network_utilization_percent(rx_delta_bytes, tx_delta_bytes, elapsed_ns, link_speed_bps)
    })
}

fn network_utilization_percent(
    rx_delta_bytes: u64,
    tx_delta_bytes: u64,
    elapsed_ns: u64,
    link_speed_bps: f64,
) -> f64 {
    if elapsed_ns == 0 || link_speed_bps <= 0.0 {
        return 0.0;
    }

    let busiest_direction_bytes = rx_delta_bytes.max(tx_delta_bytes) as f64;
    let bits_per_second = busiest_direction_bytes * 8.0 * 1_000_000_000.0 / elapsed_ns as f64;
    percent(bits_per_second, link_speed_bps)
}

fn elapsed_ns(previous: Instant, current: Instant) -> u64 {
    u64::try_from(current.saturating_duration_since(previous).as_nanos()).unwrap_or(u64::MAX)
}

fn complete_max(mut values: impl Iterator<Item = Option<f64>>) -> Option<f64> {
    values.try_fold(0.0_f64, |maximum, value| {
        value.map(|value| maximum.max(value))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_busiest_full_duplex_network_direction() {
        let utilization =
            network_utilization_percent(875_000_000, 250_000_000, 1_000_000_000, 10_000_000_000.0);

        assert_eq!(utilization, 70.0);
    }

    #[test]
    fn suppresses_network_utilization_when_counters_reset() {
        let sampled_at = Instant::now();
        let previous = NetworkCounters {
            sampled_at,
            rx_bytes: 1_000,
            tx_bytes: 2_000,
        };
        let current = NetworkCounters {
            sampled_at: sampled_at + Duration::from_secs(1),
            rx_bytes: 100,
            tx_bytes: 200,
        };

        assert_eq!(
            network_utilization_from_samples(previous, current, 1_000_000_000.0),
            None
        );
    }

    #[test]
    fn parses_all_interface_counters_from_one_snapshot() {
        let counters = parse_network_device_counters(
            "Inter-| Receive | Transmit\n eth0: 100 1 2 3 4 5 6 7 900 9 10 11 12 13 14 15\n eth1: 200 1 2 3 4 5 6 7 800 9 10 11 12 13 14 15\n",
        );

        assert_eq!(counters.get("eth0"), Some(&(100, 900)));
        assert_eq!(counters.get("eth1"), Some(&(200, 800)));
    }

    #[test]
    fn multi_interface_utilization_requires_every_interface() {
        assert_eq!(
            complete_max([Some(20.0), Some(70.0)].into_iter()),
            Some(70.0)
        );
        assert_eq!(complete_max([Some(20.0), None].into_iter()), None);
    }

    #[test]
    fn configured_capacity_supports_virtual_interfaces_without_reported_speed() {
        let mut sampler =
            NetworkInterfaceSampler::new("interface-that-does-not-exist".to_string(), Some(2_000));

        assert_eq!(sampler.link_speed_bps, Some(2_000_000_000.0));
        assert!(sampler.capacity_is_configured);

        let sampled_at = Instant::now();
        assert_eq!(sampler.sample(sampled_at, Some((0, 0))), None);
        assert_eq!(
            sampler.sample(
                sampled_at + Duration::from_secs(1),
                Some((125_000_000, 25_000_000)),
            ),
            Some(50.0)
        );
    }
}
