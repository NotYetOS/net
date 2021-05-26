// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type      |     Code      |          Checksum             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             unused                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      Internet Header + 64 bits of Original Data Datagram      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// Echo or Echo Reply Message
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type      |     Code      |          Checksum             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Identifier          |        Sequence Number        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Data ...
// +-+-+-+-+-

#![allow(unused)]
use byteorder::{
    NetworkEndian,
    ByteOrder,
};
use crate::{
    Result,
    Error,
};
use crate::checksum;

// just...
#[repr(u8)]
pub enum Message {
    EchoReply   = 0,
    EchoRequest = 8,
    Unsupported = 0xFF,
}

impl From<u8> for Message {
    fn from(val: u8) -> Self {
        match val {
            0 => Self::EchoReply,
            8 => Self::EchoRequest,
            _ => Self::Unsupported
        }
    }
}

impl From<Message> for u8 {
    fn from(msg: Message) -> Self {
        match msg {
            Message::EchoReply => 0,
            Message::EchoRequest => 8,
            Message::Unsupported => 0xFF,
        }
    }
}

mod field {
    use crate::Field;

    pub const TYPE: usize = 0;
    pub const CODE: usize = 1;
    pub const CHECKSUM: Field = 2..4;
    pub const UNUSED: Field = 4..8;

    pub const ECHO_IDENT: Field = 4..6;
    pub const ECHO_SEQNO: Field = 6..8;

    pub const HEADER_END: usize = 8;
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
        if len < field::HEADER_END {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }

    pub fn into_inner(self) -> T {
        self.buffer
    }

    pub fn msg_type(&self) -> Message {
        let data = self.buffer.as_ref();
        data[field::TYPE].into()
    }

    pub fn msg_code(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::CODE]
    }

    pub fn checksum(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::CHECKSUM])
    }

    pub fn echo_ident(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::ECHO_IDENT])
    }

    pub fn echo_seq_no(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::ECHO_SEQNO])
    }

    pub fn header_len(&self) -> usize {
        match self.msg_type() {
            Message::EchoRequest => field::ECHO_SEQNO.end,
            Message::EchoReply   => field::ECHO_SEQNO.end,
            _ => field::UNUSED.end
        }
    }

    pub fn verify_checksum(&self) -> bool {
        let data = self.buffer.as_ref();
        checksum::data(data) == !0
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    pub fn set_msg_type(&mut self, msg_type: Message) {
        let data = self.buffer.as_mut();
        data[field::TYPE] = msg_type.into();
    }

    pub fn set_msg_code(&mut self, code: u8) {
        let data = self.buffer.as_mut();
        data[field::CODE] == code;
    }

    pub fn set_checksum(&mut self, checksum: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::CHECKSUM], checksum);
    } 

    pub fn set_echo_ident(&mut self, ident: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::ECHO_IDENT], ident)
    }

    pub fn set_echo_seq_no(&mut self, number: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::ECHO_SEQNO], number)
    }

    pub fn fill_checksum(&mut self) {
        self.set_checksum(0);
        let checksum = {
            let data = self.buffer.as_ref();
            !checksum::data(data)
        };
        self.set_checksum(checksum)
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Packet<T> {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> Packet<&'a mut T> {
    pub fn data_mut(&mut self) -> &mut [u8] {
        let range = self.header_len()..;
        let data = self.buffer.as_mut();
        &mut data[range]
    }
}

#[cfg(test)]
mod test {
    use crate::protocol::ethernet;
    use crate::protocol::ethernet::EtherType;
    use crate::protocol::ethernet::Frame;
    use crate::protocol::ip::ipv4::Packet as IPv4Packet;
    use crate::protocol::ip::ipv4::Address as IPv4Address;
    use crate::protocol::ip::Protocol as IPv4Protocal;
    use crate::dev::{
        send_raw_socket,
        DST_MAC,
        src_mac,
    };

    use super::Packet as ICMPPacket;
    use super::Message;

    #[test]
    fn test_protocol() {
        let mut frame_bytes = vec![0; 14 + 32];
        let mut frame = Frame::new_unchecked(&mut frame_bytes);
        frame.set_dst_addr(ethernet::Address(DST_MAC));
        frame.set_src_addr(ethernet::Address(src_mac()));
        frame.set_ether_type(EtherType::IPv4);

        let mut bytes = vec![0; 12];
        let mut packet = ICMPPacket::new_unchecked(&mut bytes);
        packet.set_msg_type(Message::EchoRequest);
        packet.set_msg_code(0);
        packet.set_echo_ident(0x1234);
        packet.set_echo_seq_no(0xabcd);
        packet.data_mut().copy_from_slice("ABCD".as_ref());
        packet.fill_checksum();

        let mut bytes = vec![0; 32];
        let mut ipv4_packet = IPv4Packet::new_unchecked(&mut bytes);
        ipv4_packet.set_version(4);
        ipv4_packet.set_header_len(20);
        ipv4_packet.clear_flags();
        ipv4_packet.set_dscp(0);
        ipv4_packet.set_ecn(0);
        ipv4_packet.set_total_len(32);
        ipv4_packet.set_ident(0x0);
        ipv4_packet.set_more_frags(false);
        ipv4_packet.set_dont_frag(true);
        ipv4_packet.set_frag_offset(0);
        ipv4_packet.set_hop_limit(0x20);
        ipv4_packet.set_protocol(IPv4Protocal::ICMP);
        ipv4_packet.set_src_addr(IPv4Address([172, 27, 60, 82]));
        ipv4_packet.set_dst_addr(IPv4Address([10, 10, 10, 1]));
        ipv4_packet.fill_checksum();
        
        ipv4_packet.payload_mut().copy_from_slice(packet.as_ref());
        frame.payload_mut().copy_from_slice(ipv4_packet.as_ref());

        send_raw_socket(frame.as_ref());
    }
}
