#![allow(unused)]

use core::ops::{
    Deref, 
    DerefMut
};

use crate::protocol::ethernet::Frame;

use super::{
    Network, 
    NetworkInterface
};

pub struct Ethernet<T>
where
    T: AsRef<[u8]>,
{
    frame: Frame<T>,
}

// impl<T> Ethernet<T> where T: AsRef<[u8]> {
//     pub fn new()
// }

impl<T> Deref for Ethernet<T>
where
    T: AsRef<[u8]>,
{
    type Target = Frame<T>;

    fn deref(&self) -> &Self::Target {
        &self.frame
    }
}

impl<T> DerefMut for Ethernet<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.frame
    }
}

impl<T> From<Frame<T>> for Ethernet<T>
where
    T: AsRef<[u8]>,
{
    fn from(frame: Frame<T>) -> Self {
        Self { frame }
    }
}

impl<T> AsRef<[u8]> for Ethernet<T> where T: AsRef<[u8]> {
    fn as_ref(&self) -> &[u8] {
        self.frame.as_ref()
    }
}

impl<T, P> NetworkInterface<P> for Ethernet<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
    P: Network + AsRef<[u8]>,
{
    fn set_upper_protocol(&mut self, protocol: P) {
        self.payload_mut().copy_from_slice(protocol.as_ref());
    }
}

#[cfg(test)]
pub mod test {
    use crate::protocol::ethernet::{
        EtherType,
        Address,
        Frame
    };
    use crate::dev::{
        send_raw_socket,
        DST_MAC,
        src_mac,
    };
    use crate::socket::ethernet::Ethernet;
     
    #[test]
    fn test_protocol() {
        let mut bytes = vec![0; 14 + 4];
        let mut frame = Frame::new_unchecked(&mut bytes);
        frame.set_dst_addr(Address(DST_MAC));
        frame.set_src_addr(Address(src_mac()));
        frame.set_ether_type(EtherType::ECTP);
        frame.payload_mut().copy_from_slice(&[0, 0, 0, 0]);
        let ethernet: Ethernet<_> = frame.into();
        send_raw_socket(ethernet.as_ref());
    }
}
