#![allow(unused)]
use super::{
    Result,
    Error,
};

#[repr(u16)]
#[derive(Debug, PartialEq)]
pub enum EtherType {
    IPv4 = 0x0800,
    ARP  = 0x0806,
    IPv6 = 0x86DD,
    ECTP = 0x9000,
    Unsupported,
}

impl EtherType {
    pub fn value(&self) -> u16 {
        match self {
            EtherType::IPv4 => 0x0800,
            EtherType::ARP  => 0x0806,
            EtherType::IPv6 => 0x86DD,
            EtherType::ECTP => 0x9000,
            EtherType::Unsupported => 0
        }
    }

    pub fn from_bytes(data: &[u8]) -> EtherType {
        ((data[0] as u16) << 8 | data[1] as u16).into()
    }

    pub fn bytes(&self) -> [u8; 2] {
        let mut bytes = [0; 2];
        let val = self.value();
        bytes[1] = (val & 0xFF) as u8;
        bytes[0] = ((val >> 8) & 0xFF) as u8;
        bytes
    }
}

impl From<u16> for EtherType {
    fn from(val: u16) -> Self {
        match val {
            0x0800 => Self::IPv4,
            0x0806 => Self::ARP,
            0x86DD => Self::IPv6,
            _ => Self::Unsupported,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct MacAddress([u8;6]);

impl MacAddress {
    pub const BROADCAST: MacAddress = MacAddress([0xFF; 6]);

    pub fn from_bytes(data: &[u8]) -> Self {
        let mut addr = [0; 6];
        addr.copy_from_slice(&data);
        MacAddress(addr)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    } 

    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST
    }

    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 == 1
    }

    pub fn is_unicast(&self) -> bool {
        !self.is_broadcast() && !self.is_multicast()
    }

    pub fn is_local(&self) -> bool {
        self.0[0] & 0x02 != 0
    }
}

mod field {
    type Field = core::ops::Range<usize>;
    type FieldFrom = core::ops::RangeFrom<usize>;

    pub const DESTINATION: Field = 0..6;
    pub const SOURCE: Field = 6..12;
    pub const ETHERTYPE: Field = 12..14;
    pub const PAYLOAD: FieldFrom = 14..;
}

pub const HEADER_LEN: usize = field::PAYLOAD.start;

pub struct Frame<T: AsRef<[u8]>> {
    buffer: T
}

impl<T: AsRef<[u8]>> Frame<T> {
    pub fn new_unchecked(buffer: T) -> Frame<T> {
        Frame { buffer }
    }

    pub fn new_checked(buffer: T) -> Result<Frame<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < HEADER_LEN {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    pub fn into_inner(self) -> T {
        self.buffer
    }

    pub fn header_len() -> usize {
        HEADER_LEN
    }

    pub fn frame_len(payload_len: usize) -> usize {
        HEADER_LEN + payload_len
    }

    pub fn dst_addr(&self) -> MacAddress {
        let buf_ref = self.buffer.as_ref();
        MacAddress::from_bytes(&buf_ref[field::DESTINATION])
    }

    pub fn src_addr(&self) -> MacAddress {
        let buf_ref = self.buffer.as_ref();
        MacAddress::from_bytes(&buf_ref[field::SOURCE])
    }

    pub fn ether_type(&self) -> EtherType {
        let buf_ref = self.buffer.as_ref();
        let mut type_val = [0; 2];
        type_val.copy_from_slice(&buf_ref[field::ETHERTYPE]);
        EtherType::from_bytes(&type_val)
    }

    pub fn payload(&self) -> &[u8] {
        let buf_ref = self.buffer.as_ref();
        &buf_ref[field::PAYLOAD]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Frame<T> {
    pub fn set_dst_addr(&mut self, addr: MacAddress) {
        let buf_mut_ref = self.buffer.as_mut();
        buf_mut_ref[field::DESTINATION].copy_from_slice(addr.as_bytes())
    }

    pub fn set_src_addr(&mut self, addr: MacAddress) {
        let buf_mut_ref = self.buffer.as_mut();
        buf_mut_ref[field::SOURCE].copy_from_slice(addr.as_bytes())
    }

    pub fn set_ether_type(&mut self, ether_type: EtherType) {
        let buf_mut_ref = self.buffer.as_mut();
        buf_mut_ref[field::ETHERTYPE].copy_from_slice(&ether_type.bytes())
    }

    pub fn payload_mut(&mut self) -> &mut [u8] {
        let buf_mut_ref = self.buffer.as_mut();
        &mut buf_mut_ref[field::PAYLOAD]
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Frame<T> {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_broadcast() {
        assert!(MacAddress::BROADCAST.is_broadcast());
        assert!(!MacAddress::BROADCAST.is_unicast());
        assert!(MacAddress::BROADCAST.is_multicast());
        assert!(MacAddress::BROADCAST.is_local());
    }
}

#[cfg(test)]
mod test_ipv4 {
    // Tests that are valid only with "proto-ipv4"
    use super::*;

    static FRAME_BYTES: [u8; 64] =
        [0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
         0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
         0x08, 0x00,
         0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0xff];

    static PAYLOAD_BYTES: [u8; 50] =
        [0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0xff];

    #[test]
    fn test_deconstruct() {
        let frame = Frame::new_unchecked(&FRAME_BYTES[..]);
        assert_eq!(frame.dst_addr(), MacAddress([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]));
        assert_eq!(frame.src_addr(), MacAddress([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]));
        assert_eq!(frame.ether_type(), EtherType::IPv4);
        assert_eq!(frame.payload(), &PAYLOAD_BYTES[..]);
    }

    #[test]
    fn test_construct() {
        let mut bytes = vec![0xa5; 64];
        let mut frame = Frame::new_unchecked(&mut bytes);
        frame.set_dst_addr(MacAddress([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]));
        frame.set_src_addr(MacAddress([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]));
        frame.set_ether_type(EtherType::IPv4);
        frame.payload_mut().copy_from_slice(&PAYLOAD_BYTES[..]);
        assert_eq!(&frame.into_inner()[..], &FRAME_BYTES[..]);
    }
}
