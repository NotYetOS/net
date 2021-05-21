#![allow(unused)]

pub mod ipv4;
mod ipv6;

use super::{
    Error, 
    Result
};

mod checksum {
    use byteorder::{
        ByteOrder, 
        NetworkEndian,
    };

    // return checksum
    pub fn result(data: &[u8]) -> u16 {
        let mut accum = 0u32;
        for i in (0..data.len()).step_by(2) {
            if i == 10 { continue; }
            if i + 1 > data.len() { break; }
            accum += NetworkEndian::read_u16(
                &data[i..]
            ) as u32;
        }

        if data.len() % 2 != 0 {
            let &val = data.last().unwrap();
            accum += (val as u32) << 8;  
        }
        
        !((accum >> 16) as u16 + accum as u16)
    }
}

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
    Test = 0xFD,
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

impl From<Protocol> for u8 {
    fn from(protocal: Protocol) -> Self {
        match protocal {
            Protocol::HopByHop => 0x00,
            Protocol::ICMP => 0x01,
            Protocol::IGMP => 0x02,
            Protocol::TCP => 0x06,
            Protocol::UDP => 0x11,
            Protocol::IPv6Route => 0x11,
            Protocol::IPv6Frag => 0x2B,
            Protocol::ICMPv6 => 0x2C,
            Protocol::IPv6NoNxt => 0x3A,
            Protocol::IPv6Opts => 0x3C,
            Protocol::Test => 0xFD,
            Protocol::Unsupported => 0xFF,
        }
    }
}
