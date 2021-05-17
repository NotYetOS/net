#![allow(unused)]
use byteorder::{
    ByteOrder, 
    NetworkEndian
};
use super::Protocol;

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

mod field {
    use crate::Field;

    pub const VER_IHL:  usize = 0;
    pub const DSCP_ECN: usize = 1;
    pub const LENGTH:   Field = 2..4;
    pub const IDENT:    Field = 4..6;
    pub const FLG_OFF:  Field = 6..8;
    pub const TTL:      usize = 8;
    pub const PROTOCOL: usize = 9;
    pub const CHECKSUM: Field = 10..12;
    pub const SRC_ADDR: Field = 12..16;
    pub const DST_ADDR: Field = 16..20;
}

pub struct Packet<T: AsRef<[u8]>> {
    buffer: T
}

impl<T: AsRef<[u8]>> Packet<T> {
    pub fn src_addr(&self) -> Address {
        let buf_ref = self.buffer.as_ref();
        Address::from_bytes(&buf_ref[field::SRC_ADDR])
    }

    pub fn dst_addr(&self) -> Address {
        let buf_ref = self.buffer.as_ref();
        Address::from_bytes(&buf_ref[field::DST_ADDR])
    } 

    pub fn checksum(&self) -> u16 {
        let buf_ref = self.buffer.as_ref();
        NetworkEndian::read_u16(&buf_ref[field::CHECKSUM])
    }

    pub fn protocol(&self) -> Protocol {
        let buf_ref = self.buffer.as_ref();
        buf_ref[field::PROTOCOL].into()
    }
}
