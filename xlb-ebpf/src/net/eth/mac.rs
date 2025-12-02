#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr {
    addr: [u8; 6],
}

impl MacAddr {
    pub fn new(addr: [u8; 6]) -> Self {
        Self { addr }
    }

    pub fn from_u64(val: u64) -> Self {
        Self {
            addr: [
                (val >> 40) as u8,
                (val >> 32) as u8,
                (val >> 24) as u8,
                (val >> 16) as u8,
                (val >> 8) as u8,
                val as u8,
            ],
        }
    }

    pub fn to_u64(self) -> u64 {
        ((self.addr[0] as u64) << 40)
            | ((self.addr[1] as u64) << 32)
            | ((self.addr[2] as u64) << 24)
            | ((self.addr[3] as u64) << 16)
            | ((self.addr[4] as u64) << 8)
            | (self.addr[5] as u64)
    }

    pub fn as_bytes(&self) -> [u8; 6] {
        self.addr
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(addr: [u8; 6]) -> Self {
        Self::new(addr)
    }
}

impl From<MacAddr> for [u8; 6] {
    fn from(mac: MacAddr) -> Self {
        mac.as_bytes()
    }
}

impl From<MacAddr> for u64 {
    fn from(mac: MacAddr) -> Self {
        mac.to_u64()
    }
}

impl From<u64> for MacAddr {
    fn from(val: u64) -> Self {
        Self::from_u64(val)
    }
}

impl core::fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(
            f,
            "MacAddr({:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
            self.addr[0], self.addr[1], self.addr[2], self.addr[3], self.addr[4], self.addr[5]
        )
    }
}

#[cfg(not(target_os = "none"))]
impl core::fmt::Display for MacAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.addr[0], self.addr[1], self.addr[2], self.addr[3], self.addr[4], self.addr[5]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_bytes() {
        let bytes = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mac = MacAddr::new(bytes);
        assert_eq!(mac.as_bytes(), bytes);
    }

    #[test]
    fn test_from_u64() {
        let mac = MacAddr::from(0x001122334455u64);
        assert_eq!(mac.as_bytes(), [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    }

    #[test]
    fn test_to_u64() {
        let mac = MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let val: u64 = mac.into();
        assert_eq!(val, 0x001122334455u64);
    }

    #[test]
    fn test_roundtrip_u64() {
        let original = 0xAABBCCDDEEFFu64;
        let mac = MacAddr::from(original);
        let result: u64 = mac.into();
        assert_eq!(original, result);
    }

    #[test]
    fn test_roundtrip_bytes() {
        let original = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let mac = MacAddr::new(original);
        let result = mac.as_bytes();
        assert_eq!(original, result);
    }

    #[test]
    fn test_all_zeros() {
        let mac = MacAddr::from(0u64);
        assert_eq!(mac.as_bytes(), [0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_all_ones() {
        let mac = MacAddr::from(0xFFFFFFFFFFFFu64);
        assert_eq!(mac.as_bytes(), [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_broadcast_mac() {
        let broadcast = MacAddr::new([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(u64::from(broadcast), 0xFFFFFFFFFFFFu64);
    }

    #[test]
    fn test_into_from_bytes() {
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let mac: MacAddr = bytes.into();
        let result: [u8; 6] = mac.into();
        assert_eq!(bytes, result);
    }

    #[test]
    fn test_equality() {
        let mac1 = MacAddr::from(0x112233445566u64);
        let mac2 = MacAddr::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        assert_eq!(mac1, mac2);
    }

    #[test]
    fn test_copy_trait() {
        let mac1 = MacAddr::from(0x112233445566u64);
        let mac2 = mac1;
        assert_eq!(mac1, mac2);
        assert_eq!(u64::from(mac1), 0x112233445566u64);
    }
}
