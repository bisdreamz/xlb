use strum::IntoStaticStr;

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
}
