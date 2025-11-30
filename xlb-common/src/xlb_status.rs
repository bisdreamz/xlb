use strum::IntoStaticStr;

#[derive(Clone, Copy, PartialEq, Eq, IntoStaticStr)]
#[cfg_attr(not(target_os = "none"), derive(Debug))]
pub enum XlbStatus {
    Ok,
    ErrParseHdrEth,
    ErrParseHdrIp,
    ErrParseHdrProto,
}
