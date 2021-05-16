mod ipv4;
mod ipv6;

use super::{
    Error, 
    Result
};

pub enum Version {
    IPv4,
    IPv6,
    Unsupported,
}

impl Version {
    pub fn of_packet(data: &[u8]) -> Result<Version> {
        // version and IHL = 8 bits
        match data[0] >> 4 {
            4 => Ok(Version::IPv4),
            6 => Ok(Version::IPv6),
            _ => Err(Error::Unrecognized)
        }
    }
}

#[repr(u8)]
pub enum Protocol {
    HopByHop  = 0x00,
    ICMP      = 0x01,
    IGMP      = 0x02,
    TCP       = 0x06,
    UDP       = 0x11,
    IPv6Route = 0x2b,
    IPv6Frag  = 0x2c,
    Icmpv6    = 0x3a,
    IPv6NoNxt = 0x3b,
    IPv6Opts  = 0x3c,
    Unsupported,
}
