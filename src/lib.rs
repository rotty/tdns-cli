pub mod record;
pub mod update;
pub mod update_message;
pub mod util;

mod open;

pub use open::{DnsOpen, RuntimeHandle, TcpOpen, UdpOpen};
