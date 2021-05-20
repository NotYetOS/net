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

#![allow(unused)]
use byteorder::{
    ByteOrder, 
    NetworkEndian,
};
use crate::{
    Result,
    Error,
};
use super::Protocol;
use crate::checksum;

#[derive(Debug, PartialEq)]
pub struct Address(pub [u8; 4]);

impl Address {
    pub const UNSPECIFIED:           Address = Address([0x00; 4]);
    pub const BROADCAST:             Address = Address([0xFF; 4]);
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
    pub fn new_unchecked(buffer: T) -> Packet<T> {
        Packet { buffer }
    }

    pub fn new_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < field::DST_ADDR.end {
            Err(Error::Truncated)
        } else if len < self.header_len() as usize {
            Err(Error::Truncated)
        } else if self.header_len() as u16 > self.total_len() {
            Err(Error::Malformed)
        } else if len < self.total_len() as usize {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    pub fn into_inner(self) -> T {
        self.buffer
    }

    pub fn version(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::VER_IHL] >> 4
    }

    // Internet Header Length is the length of the internet header in 32
    // bit words
    pub fn header_len(&self) -> u8 {
        let data = self.buffer.as_ref();
        (data[field::VER_IHL] & 0x0F) << 2
    }

    pub fn dscp(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::DSCP_ECN] >> 2
    }

    pub fn ecn(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::DSCP_ECN] & 0x03
    }

    pub fn total_len(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::LENGTH])
    }

    pub fn ident(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::IDENT])
    }

    pub fn dont_frag(&self) -> bool {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::FLG_OFF]) & 0x4000 != 0
    }

    pub fn more_frags(&self) -> bool {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::FLG_OFF]) & 0x2000 != 0
    }

    // The fragment offset is measured in units of 8 octets (64 bits).
    pub fn frag_offset(&self) -> u16 {
        let data = self.buffer.as_ref();
        // 0x0001_1111_1111_1111 = 0x1FFF
        NetworkEndian::read_u16(&data[field::FLG_OFF]) << 3
    }

    pub fn hop_limit(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::TTL]    
    }

    pub fn protocol(&self) -> Protocol {
        let data = self.buffer.as_ref();
        data[field::PROTOCOL].into()
    }

    pub fn checksum(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::CHECKSUM])
    }

    pub fn src_addr(&self) -> Address {
        let data = self.buffer.as_ref();
        Address::from_bytes(&data[field::SRC_ADDR])
    }

    pub fn dst_addr(&self) -> Address {
        let data = self.buffer.as_ref();
        Address::from_bytes(&data[field::DST_ADDR])
    }

    pub fn verify_checksum(&self) -> bool {
        let data = self.buffer.as_ref();
        checksum::data(
            &data[..self.header_len() as usize]
        ) == !0
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    pub fn set_version(&mut self, version: u8) {
        let data = self.buffer.as_mut();
        let new = (version & 0x0F) << 4 | (0x0F & data[field::VER_IHL]);
        data[field::VER_IHL] = new;
    }

    pub fn set_header_len(&mut self, len: u8) {
        let data = self.buffer.as_mut();
        let new = (data[field::VER_IHL] & 0xF0) | ((len >> 2) & 0x0F);
        data[field::VER_IHL] = new;
    }

    pub fn set_dscp(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        let new = (data[field::DSCP_ECN] & !0xFC) | (value << 2);
        data[field::DSCP_ECN] = new;
    }

    pub fn set_ecn(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        let new = (data[field::DSCP_ECN] & !0x03) | (value & 0x03);
        data[field::DSCP_ECN] = new;
    }

    pub fn set_total_len(&mut self, len: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::LENGTH], len);
    } 

    pub fn set_ident(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::IDENT], value);
    }

    pub fn clear_flags(&mut self) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLG_OFF]);
        let raw = raw & !0xE000;
        NetworkEndian::write_u16(&mut data[field::FLG_OFF], raw);
    }

    pub fn set_dont_frag(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLG_OFF]);
        let raw = if value { raw | 0x4000 } else { raw & !0x4000 };
        NetworkEndian::write_u16(&mut data[field::FLG_OFF], raw);
    }

    pub fn set_more_frags(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLG_OFF]);
        let raw = if value { raw | 0x2000 } else { raw & !0x2000 };
        NetworkEndian::write_u16(&mut data[field::FLG_OFF], raw);
    }

    // The fragment offset is measured in units of 8 octets (64 bits).
    pub fn set_frag_offset(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLG_OFF]);
        let raw = (raw & 0xE000) | (value >> 3);
        NetworkEndian::write_u16(&mut data[field::FLG_OFF], raw);
    }

    pub fn set_hop_limit(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::TTL] = value;
    }

    pub fn set_protocol(&mut self, protocol: Protocol) {
        let data = self.buffer.as_mut();
        data[field::PROTOCOL] = protocol.into();
    }

    pub fn set_checksum(&mut self, checksum: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::CHECKSUM], checksum);
    }

    pub fn set_src_addr(&mut self, addr: Address) {
        let data = self.buffer.as_mut();
        data[field::SRC_ADDR].copy_from_slice(addr.as_bytes());
    }

    pub fn set_dst_addr(&mut self, addr: Address) {
        let data = self.buffer.as_mut();
        data[field::DST_ADDR].copy_from_slice(addr.as_bytes());
    }

    pub fn fill_checksum(&mut self) {
        self.set_checksum(0);
        let checksum = {
            let data = self.buffer.as_ref();
            !checksum::data(data)
        };
        self.set_checksum(checksum);
    }
    
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let range = self.header_len() as usize..self.total_len() as usize;
        let data = self.buffer.as_mut();
        &mut data[range]
    }
} 

impl<T: AsRef<[u8]>> AsRef<[u8]> for Packet<T> {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

#[cfg(test)]
mod test {
    use crate::ethernet;
    use crate::ethernet::EtherType;
    use crate::ethernet::Frame;
    use crate::dev::send_raw_socket;

    use super::Packet;
    use super::Protocol;

    #[test]
    fn test_protocol() {
        let mut frame_bytes = vec![0; 64];
        let mut frame = Frame::new_unchecked(&mut frame_bytes);
        frame.set_dst_addr(ethernet::Address(ethernet::test::DST_MAC));
        frame.set_src_addr(ethernet::Address(ethernet::test::SRC_MAC));
        frame.set_ether_type(EtherType::IPv4);

        let mut bytes = vec![0; 50];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_version(4);
        packet.set_header_len(20);
        packet.clear_flags();
        packet.set_dscp(0);
        packet.set_ecn(0);
        packet.set_total_len(30);
        packet.set_ident(0x0);
        packet.set_more_frags(false);
        packet.set_dont_frag(false);
        packet.set_frag_offset(0);
        packet.set_hop_limit(0x20);
        packet.set_protocol(Protocol::Test);
        packet.set_src_addr(super::Address([171, 24, 16, 35]));
        packet.set_dst_addr(super::Address([10, 10, 10, 1]));
        packet.fill_checksum();
        frame.payload_mut().copy_from_slice(packet.as_ref());

        send_raw_socket(frame.as_ref());
    }
}
