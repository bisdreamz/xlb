use aya_ebpf::maps::Array;
use xlb_common::config::ebpf::Strategy;
use xlb_common::types::Backend;
use crate::balancing::roundrobin;

pub fn select_backend(strategy: &Strategy, backends: &'static Array<Backend>) -> Option<&'static Backend> {
    match strategy {
        Strategy::RoundRobin => roundrobin::select_backend(backends),
    }
}
