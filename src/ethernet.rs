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
            EtherType::Unsupported => 0xFFFF
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct Address(pub [u8;6]);

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
        let data = self.buffer.as_ref();
        Address::from_bytes(&data[field::DESTINATION])
    }

    pub fn src_addr(&self) -> Address {
        let data = self.buffer.as_ref();
        Address::from_bytes(&data[field::SOURCE])
    }

    pub fn ether_type(&self) -> EtherType {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::ETHERTYPE]);
        raw.into()
    }

    pub fn payload(&self) -> &[u8] {
        let data = self.buffer.as_ref();
        &data[field::PAYLOAD]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Frame<T> {
    pub fn set_dst_addr(&mut self, addr: Address) {
        let data = self.buffer.as_mut();
        data[field::DESTINATION].copy_from_slice(addr.as_bytes())
    }

    pub fn set_src_addr(&mut self, addr: Address) {
        let data = self.buffer.as_mut();
        data[field::SOURCE].copy_from_slice(addr.as_bytes())
    }

    pub fn set_ether_type(&mut self, ether_type: EtherType) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(
            &mut data[field::ETHERTYPE], 
            ether_type.into()
        )
    }

    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[field::PAYLOAD]
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Frame<T> {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::dev::{
        send_raw_socket,
        DST_MAC,
        SRC_MAC,
    };

    static PAYLOAD_BYTES: [u8; 50] =
    [0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0xff];
     
    #[test]
    fn test_protocol() {
        let mut bytes = vec![0xa5; 64];
        let mut frame = Frame::new_unchecked(&mut bytes);
        frame.set_dst_addr(Address(DST_MAC));
        frame.set_src_addr(Address(SRC_MAC));
        frame.set_ether_type(EtherType::ECTP);
        frame.payload_mut().copy_from_slice(&PAYLOAD_BYTES[..]);

        send_raw_socket(frame.as_ref());
    }
}
