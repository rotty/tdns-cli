pub mod query;
pub mod record;
pub mod tsig;
pub mod update;
pub mod update_message;
pub mod util;

mod backend;

pub use backend::{Backend, Resolver, RuntimeHandle, TcpBackend, UdpBackend};
