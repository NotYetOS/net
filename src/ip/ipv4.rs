// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Version|  IHL  |Type of Service|          Total Length         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Identification        |Flags|      Fragment Offset    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Time to Live |    Protocol   |         Header Checksum       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Source Address                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Destination Address                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Options                    |    Padding    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[derive(Debug, PartialEq)]
pub struct Address(pub [u8; 4]);

impl Address {
    pub const UNSPECIFIED:           Address = Address([0x00; 4]);
    pub const BROADCAST:             Address = Address([0xff; 4]);
    pub const MUILTCAST_ALL_SYSTEMS: Address = Address([224, 0, 0, 1]);
    pub const MUILICAST_ALL_ROUTERS: Address = Address([224, 0, 0, 2]);

    pub fn new(a0: u8, a1: u8, a2: u8, a3: u8) -> Self {
        Address([a0, a1, a2, a3])
    }

    pub fn from_bytes(data: &[u8]) -> Self {
        let mut bytes = [0; 4];
        bytes.copy_from_slice(data);
        Address(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST 
    }

    pub fn is_unspecified(&self) -> bool {
        *self == Self::UNSPECIFIED
    }

    pub fn is_multicast(&self) -> bool {
        self.0[0] == 224
    }

    pub fn is_link_local(&self) -> bool {
        self.0[0..2] == [169, 254]
    }

    pub fn is_loopback(&self) -> bool {
        self.0[0] == 127
    }

    pub fn is_unicast(&self) -> bool {
        !self.is_broadcast() &&
        !self.is_multicast() &&
        !self.is_unspecified()
    }
}
