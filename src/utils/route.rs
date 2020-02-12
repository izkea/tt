extern crate nell;

use nell::ffi::route::rtmsg;
use nell::sys::{Message, Cursor};
use std::net::{IpAddr, Ipv4Addr};

pub struct Route {
    pub sock_fd: i32,
    pub msg_cur: Cursor, 
    pub bytes: Vec<u8>,
}


impl Route {
    pub fn new() -> Route {
        let sock_fd = unsafe {
            libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM, nell::sys::Family::Route as libc::c_int)
        };

        Route { 
            sock_fd: sock_fd,
            msg_cur: Cursor::default(),
            bytes:  vec![0x24, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x01, 0x00, 
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                            0x00, 0x10, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00, 
                            0x08, 0x08, 0x08, 0x08],
        }
    }

    pub fn lookup(&mut self, dst: &Ipv4Addr) -> Option<IpAddr> {
        let mut buf = [0u8; 1024];
        self.bytes[32..].copy_from_slice(&dst.octets());

        let rtmsg = unsafe {
            libc::write(self.sock_fd, self.bytes.as_ptr() as *const _, self.bytes.len());
            let len = libc::read(self.sock_fd, buf.as_mut_ptr() as *mut _, buf.len());
            self.msg_cur.reset(buf.as_mut_ptr(), len as usize);

            match self.msg_cur.next::<Message<rtmsg>>() {
                Some(msg) => msg.get(),
                None      => Ok(nell::Netlink::None),
            }
        };

        if let Ok(nell::sys::Netlink::Msg(msg)) = rtmsg {
            if let Ok(msg) = nell::api::route(msg) {
                return msg.gateway
            }
        };
        
        None
    }
}
