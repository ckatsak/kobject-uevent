//! To build:
//!
//! ```console
//! $ cargo run --example listen_uevents_async
//! ```
//!
//! To generate events, run *as root*:
//!
//! ```console
//! # find /sys -name uevent -exec sh -c 'echo add >"{}"' ';'
//! ```

use std::process;

use netlink_sys::{
    AsyncSocket, AsyncSocketExt, SocketAddr, TokioSocket, protocols::NETLINK_KOBJECT_UEVENT,
};

use kobject_uevent::UEvent;

#[tokio::main]
async fn main() {
    let mut socket =
        TokioSocket::new(NETLINK_KOBJECT_UEVENT).expect("failed to create TokioSocket");
    socket
        .socket_mut()
        .bind(&SocketAddr::new(process::id(), 1))
        .expect("bind(2) failed");

    while let Ok((buf, _addr)) = socket.recv_from_full().await {
        let s = ::std::str::from_utf8(&buf).expect("invalid UTF-8 packet");
        let u = UEvent::from_netlink_packet(&buf).expect("failed to parse UEvent");
        println!(">> {s}");
        println!("{u:#?}");
    }
}
