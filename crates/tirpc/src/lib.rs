//! The parts of libtirpc 1.3.7 that rpcbind and rpcinfo use, reimplemented: XDR, RPC
//! messages and authentication, the record-marking stream protocol, the datagram, stream
//! and local transports, the service dispatcher, the stream and datagram clients, the
//! rpcbind client calls, broadcast, `/etc/netconfig`, `NETPATH` and universal addresses.
//! Each module names the libtirpc file it follows.

pub mod addr;
pub mod bcast;
pub mod clnt;
pub mod netconfig;
pub mod nettype;
pub mod rpc;
pub mod rpcb_clnt;
pub mod rpcb_prot;
pub mod svc;
pub mod sys;
pub mod xdr;
pub mod xdr_rec;
