use crate::protocol::ip::ipv4::Packet as IPv4Packet;
use core::ops::{
    Deref,
    DerefMut,
};

use super::Network;

pub struct IPv4<T>
where
    T: AsRef<[u8]>,
{
    packet: IPv4Packet<T>,
}

impl<T> Deref for IPv4<T> 
where 
    T: AsRef<[u8]>
{
    type Target = IPv4Packet<T>;

    fn deref(&self) -> &Self::Target {
        &self.packet
    }
}

impl<T> DerefMut for IPv4<T>
where 
    T: AsRef<[u8]> + AsMut<[u8]>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.packet
    }
}

impl<T> From<IPv4Packet<T>> for IPv4<T> where T: AsRef<[u8]> {
    fn from(packet: IPv4Packet<T>) -> Self {
        Self { packet }
    }
}

impl<T> AsRef<[u8]> for IPv4<T> where T: AsRef<[u8]> {
    fn as_ref(&self) -> &[u8] {
        self.packet.as_ref()
    }
}

impl<T> Network for IPv4<T>
where 
    T: AsRef<[u8]>
{

}

#[cfg(test)]
mod test {
    use crate::protocol::ethernet::Address as MacAddress;
    use crate::protocol::ethernet::EtherType;
    use crate::protocol::ethernet::Frame;
    use crate::dev::{
        send_raw_socket,
        DST_MAC,
        src_mac,
    };
    use crate::protocol::ip::Protocol;
    use crate::protocol::ip::ipv4::{
        Packet,
        Address as IPAddress,
    };
    use crate::socket::NetworkInterface;
    use crate::socket::ethernet::Ethernet;
    use super::IPv4;

    #[test]
    fn test_protocol() {
        let mut frame_bytes = vec![0; 14 + 20];
        let mut frame = Frame::new_unchecked(&mut frame_bytes);
        frame.set_dst_addr(MacAddress(DST_MAC));
        frame.set_src_addr(MacAddress(src_mac()));
        frame.set_ether_type(EtherType::IPv4);
        let mut ethernet: Ethernet<_> = frame.into();

        let mut bytes = vec![0; 20];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_version(4);
        packet.set_header_len(20);
        packet.clear_flags();
        packet.set_dscp(0);
        packet.set_ecn(0);
        packet.set_total_len(20);
        packet.set_ident(0x0);
        packet.set_more_frags(false);
        packet.set_dont_frag(true);
        packet.set_frag_offset(0);
        packet.set_hop_limit(0x20);
        packet.set_protocol(Protocol::Test);
        packet.set_src_addr(IPAddress([0, 0, 0, 0]));
        packet.set_dst_addr(IPAddress([10, 10, 10, 1]));
        packet.fill_checksum();
        let ip: IPv4<_> = packet.into();
        ethernet.set_upper_protocol(ip);
        send_raw_socket(ethernet.as_ref());
    }
}
