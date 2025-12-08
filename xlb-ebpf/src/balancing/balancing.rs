use crate::balancing::roundrobin;
use aya_ebpf::maps::Array;
use xlb_common::config::ebpf::Strategy;
use xlb_common::types::Backend;

pub fn select_backend(
    strategy: &Strategy,
    backends: &'static Array<Backend>,
) -> Option<&'static Backend> {
    match strategy {
        Strategy::RoundRobin => roundrobin::select_backend(backends),
    }
}
