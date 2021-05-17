#![allow(unused)]
use super::{
    Result,
    Error,
};

use byteorder::{
    NetworkEndian,
    ByteOrder,
};

#[repr(u16)]
#[derive(Debug, PartialEq)]
pub enum EtherType {
    IPv4 = 0x0800,
    ARP  = 0x0806,
    IPv6 = 0x86DD,
    ECTP = 0x9000,
    Unsupported = 0xFFFF,
}

impl From<u16> for EtherType {
    fn from(val: u16) -> Self {
        match val {
            0x0800 => Self::IPv4,
            0x0806 => Self::ARP,
            0x86DD => Self::IPv6,
            0x9000 => Self::ECTP,
            _ => Self::Unsupported,
        }
    }
}

impl From<EtherType> for u16 {
    fn from(ether_type: EtherType) -> Self {
        match ether_type {
            EtherType::IPv4 => 0x0800,
            EtherType::ARP  => 0x0806,
            EtherType::IPv6 => 0x86DD,
            EtherType::ECTP => 0x9000,
            _ => 0xFFFF
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct Address([u8;6]);

impl Address {
    pub const BROADCAST: Address = Address([0xFF; 6]);

    pub fn from_bytes(data: &[u8]) -> Self {
        let mut addr = [0; 6];
        addr.copy_from_slice(&data);
        Address(addr)
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
    use crate::{
        Field,
        FieldFrom,
    };

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

    pub fn dst_addr(&self) -> Address {
        let buf_ref = self.buffer.as_ref();
        Address::from_bytes(&buf_ref[field::DESTINATION])
    }

    pub fn src_addr(&self) -> Address {
        let buf_ref = self.buffer.as_ref();
        Address::from_bytes(&buf_ref[field::SOURCE])
    }

    pub fn ether_type(&self) -> EtherType {
        let buf_ref = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&buf_ref[field::ETHERTYPE]);
        raw.into()
    }

    pub fn payload(&self) -> &[u8] {
        let buf_ref = self.buffer.as_ref();
        &buf_ref[field::PAYLOAD]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Frame<T> {
    pub fn set_dst_addr(&mut self, addr: Address) {
        let buf_mut_ref = self.buffer.as_mut();
        buf_mut_ref[field::DESTINATION].copy_from_slice(addr.as_bytes())
    }

    pub fn set_src_addr(&mut self, addr: Address) {
        let buf_mut_ref = self.buffer.as_mut();
        buf_mut_ref[field::SOURCE].copy_from_slice(addr.as_bytes())
    }

    pub fn set_ether_type(&mut self, ether_type: EtherType) {
        let buf_mut_ref = self.buffer.as_mut();
        NetworkEndian::write_u16(
            &mut buf_mut_ref[field::ETHERTYPE], 
            ether_type.into()
        )
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
        assert!(Address::BROADCAST.is_broadcast());
        assert!(!Address::BROADCAST.is_unicast());
        assert!(Address::BROADCAST.is_multicast());
        assert!(Address::BROADCAST.is_local());
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
        assert_eq!(frame.dst_addr(), Address([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]));
        assert_eq!(frame.src_addr(), Address([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]));
        assert_eq!(frame.ether_type(), EtherType::IPv4);
        assert_eq!(frame.payload(), &PAYLOAD_BYTES[..]);
    }

    #[test]
    fn test_construct() {
        let mut bytes = vec![0xa5; 64];
        let mut frame = Frame::new_unchecked(&mut bytes);
        frame.set_dst_addr(Address([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]));
        frame.set_src_addr(Address([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]));
        frame.set_ether_type(EtherType::IPv4);
        frame.payload_mut().copy_from_slice(&PAYLOAD_BYTES[..]);
        assert_eq!(&frame.into_inner()[..], &FRAME_BYTES[..]);
    }
}

#[cfg(test)]
mod test_dev {
    use super::*;

    static PAYLOAD_BYTES: [u8; 50] =
        [0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0xff];
         
    #[test]
    fn test_protocol_through_raw_socket() {
        use rawsock::open_best_library;

        const ICMP_PACKET: [u8; 98] = [
            0x00, 0x15, 0x5d, 0xdb, 0x4d, 0xb4, 0x00, 0x15, 0x5d, 0x07, 0x2f, 0x7c, 0x08, 0x00,0x45, 0x00,
            0x00, 0x54, 0xda, 0x0d, 0x40, 0x00, 0x40, 0x01, 0xc2, 0x2c, 0xac, 0x14, 0x85, 0x6f, 0x27, 0x9c,
            0x45, 0x4f, 0x08, 0x00, 0x05, 0xb2, 0x07, 0x11, 0x00, 0x03, 0xa5, 0x63, 0x9e, 0x60, 0x00, 0x00,
            0x00, 0x00, 0xe2, 0xa2, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
            0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
            0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
            0x36, 0x37                                          
        ];

        let mut bytes = vec![0xa5; 64];
        let mut frame = Frame::new_unchecked(&mut bytes);
        frame.set_dst_addr(Address([0x00, 0x15, 0x5d, 0xdb, 0x4d, 0xb4]));
        frame.set_src_addr(Address([0x00, 0x15, 0x5d, 0x07, 0x2f, 0x7c]));
        frame.set_ether_type(EtherType::ECTP);
        frame.payload_mut().copy_from_slice(&PAYLOAD_BYTES[..]);

        let interf_name = "eth0";
        let lib = open_best_library().expect("Could not open any packet capturing library");
        let interf_result = lib.open_interface(&interf_name);
        match interf_result {
            Ok(interf) => for i in 0..5 {
                interf.send(frame.as_ref()).expect("Could not send packet");
            }
            Err(_) => {}
        }
    }
}
