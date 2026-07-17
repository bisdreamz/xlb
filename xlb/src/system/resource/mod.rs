mod cpu;
mod network;

use cpu::CpuSampler;
use network::NetworkSampler;
use xlb_common::consts;

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct ResourceUtilization {
    pub cpu_percent: Option<f64>,
    pub host_cpu_percent: Option<f64>,
    pub process_cpu_percent: Option<f64>,
    pub network_percent: Option<f64>,
    pub flow_map_percent: Option<f64>,
    pub overall_percent: Option<f64>,
}

impl ResourceUtilization {
    fn from_components(
        host_cpu_percent: Option<f64>,
        process_cpu_percent: Option<f64>,
        network_percent: Option<f64>,
        flow_entries: u64,
        flow_map_complete: bool,
    ) -> Self {
        let cpu_percent = host_cpu_percent
            .zip(process_cpu_percent)
            .map(|(host, process)| host.max(process));
        let flow_map_percent = flow_map_complete
            .then(|| percent(flow_entries as f64, f64::from(consts::MAX_ACTIVE_FLOWS)));
        let overall_percent = cpu_percent
            .zip(network_percent)
            .zip(flow_map_percent)
            .map(|((cpu, network), flow_map)| cpu.max(network).max(flow_map));

        Self {
            cpu_percent,
            host_cpu_percent,
            process_cpu_percent,
            network_percent,
            flow_map_percent,
            overall_percent,
        }
    }
}

/// Samples the resources that bound one XLB instance.
///
/// Host CPU includes kernel and softirq work performed by XDP. Network
/// utilization is the busiest RX/TX direction across every interface where
/// XLB successfully attached. Flow-map utilization uses the map's compile-time
/// directional-entry capacity.
pub struct ResourceSampler {
    cpu: CpuSampler,
    network: NetworkSampler,
}

impl ResourceSampler {
    #[must_use]
    pub fn new(attached_interfaces: Vec<String>) -> Self {
        Self {
            cpu: CpuSampler::new(),
            network: NetworkSampler::new(attached_interfaces),
        }
    }

    pub fn sample(&mut self, flow_entries: u64, flow_map_complete: bool) -> ResourceUtilization {
        let cpu = self.cpu.sample();
        let network_percent = self.network.sample();

        ResourceUtilization::from_components(
            cpu.host_percent,
            cpu.process_percent,
            network_percent,
            flow_entries,
            flow_map_complete,
        )
    }
}

fn percent(value: f64, capacity: f64) -> f64 {
    if capacity <= 0.0 {
        return 0.0;
    }

    (value / capacity * 100.0).clamp(0.0, 100.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overall_resource_utilization_is_the_largest_component() {
        let utilization = ResourceUtilization::from_components(
            Some(45.0),
            Some(60.0),
            Some(72.0),
            u64::from(consts::MAX_ACTIVE_FLOWS) / 2,
            true,
        );

        assert_eq!(utilization.cpu_percent, Some(60.0));
        assert_eq!(utilization.flow_map_percent, Some(50.0));
        assert_eq!(utilization.overall_percent, Some(72.0));
    }

    #[test]
    fn overall_resource_utilization_requires_all_sampled_components() {
        let utilization = ResourceUtilization::from_components(
            Some(45.0),
            Some(55.0),
            None,
            u64::from(consts::MAX_ACTIVE_FLOWS),
            true,
        );

        assert_eq!(utilization.flow_map_percent, Some(100.0));
        assert_eq!(utilization.overall_percent, None);
    }

    #[test]
    fn incomplete_flow_snapshot_suppresses_flow_and_overall_utilization() {
        let utilization =
            ResourceUtilization::from_components(Some(45.0), Some(55.0), Some(65.0), 10, false);

        assert_eq!(utilization.flow_map_percent, None);
        assert_eq!(utilization.overall_percent, None);
    }

    #[test]
    fn percentages_are_bounded() {
        assert_eq!(percent(150.0, 100.0), 100.0);
        assert_eq!(percent(0.0, 100.0), 0.0);
        assert_eq!(percent(100.0, 0.0), 0.0);
    }
}
