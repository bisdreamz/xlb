use strum::IntoStaticStr;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, IntoStaticStr)]
#[cfg_attr(not(target_os = "none"), derive(Debug))]
pub enum XlbErr {
    ErrParseHdrEth,
    ErrParseHdrIp,
    ErrParseHdrProto,
    /// An attempt was made to perform some operation
    /// that does not apply, e.g. rst to a udp packet
    ErrInvalidOp,
    ErrNotYetImpl,
    ErrInvalidIpVal,
    /// A syn was received when not expexted,
    /// e.g. from a backend!
    ErrUnexpectedSyn,
    /// No available backends
    ErrNoBackends,
    /// Fib iface lookup failed finding egress interface
    /// to reach the backend ip address
    ErrFibLookupFailed,
    /// Flow looks like an active connection but
    /// was not in flow map. Likely a valid conn but
    /// so inactive it was pruned as an orphan
    ErrOrphanedFlow,
    /// Failed to insert flow into map
    ErrMapInsertFailed,
    /// Unable to find available ephemeral port
    ErrNoEphemeralPorts
}
