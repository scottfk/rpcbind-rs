//! The parts of libtirpc 1.3.7 that rpcbind and rpcinfo use, reimplemented: XDR, RPC
//! messages and authentication, the record-marking stream protocol, the datagram, stream
//! and local transports, the service dispatcher, `/etc/netconfig` and universal
//! addresses. Each module names the libtirpc file it follows.

pub mod addr;
pub mod netconfig;
pub mod sys;
