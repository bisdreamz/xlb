use aya_ebpf::maps::Array;
use aya_ebpf::macros::map;
use xlb_common::types::Backend;
use xlb_common::consts;

#[map(name = "RR_COUNTER")]
static RR_COUNTER: Array<u32> = Array::with_max_entries(1, 0);

pub fn select_backend(backends: &'static Array<Backend>) -> Option<&'static Backend> {
    let start_idx = RR_COUNTER.get(0)
        .map(|v| *v)
        .unwrap_or(0);

    // Search up to 64 backends starting from current position
    for offset in 0..64 {
        let idx = (start_idx + offset) % consts::MAX_BACKENDS;

        if let Some(entry) = backends.get(idx) {
            if entry.ip != 0 {
                // Update counter for next selection
                let next_idx = (idx + 1) % consts::MAX_BACKENDS;
                let _ = RR_COUNTER.set(0, &next_idx, 0);
                return Some(entry);
            }
        }
    }

    // Nothing found in range starting from start_idx, try from beginning if we didn't start there
    if start_idx != 0 {
        for idx in 0..64 {
            if let Some(entry) = backends.get(idx) {
                if entry.ip != 0 {
                    let next_idx = (idx + 1) % consts::MAX_BACKENDS;
                    let _ = RR_COUNTER.set(0, &next_idx, 0);
                    return Some(entry);
                }
            }
        }
    }

    None
}
