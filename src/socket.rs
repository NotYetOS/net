mod ethernet;
mod icmp;
mod ip;

pub trait NetworkInterface<P>
where
    P: Network + AsRef<[u8]>,
{
    fn set_upper_protocol(&mut self, protocol: P);
}

pub trait Network {}
pub trait Transport {}
pub trait Application {}
