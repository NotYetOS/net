#![allow(unused)]

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
    IPv6Route = 0x2B,
    IPv6Frag  = 0x2C,
    ICMPv6    = 0x3A,
    IPv6NoNxt = 0x3B,
    IPv6Opts  = 0x3C,
    Unsupported = 0xFF,
}

impl From<u8> for Protocol {
    fn from(val: u8) -> Self {
        match val {
            0x00 => Self::HopByHop,
            0x01 => Self::ICMP,
            0x02 => Self::IGMP,
            0x06 => Self::TCP,
            0x11 => Self::UDP,
            0x2B => Self::IPv6Route,
            0x2C => Self::IPv6Frag,
            0x3A => Self::ICMPv6,
            0x3B => Self::IPv6NoNxt,
            0x3C => Self::IPv6Opts,
            _ => Self::Unsupported
        }
    }
}
