#![allow(non_snake_case)]
use std::mem::size_of;
use libc::{self, c_char, close, sa_family_t, sockaddr_un, socket, socklen_t, AF_UNIX, SOCK_SEQPACKET};

pub fn connect(path: &str) -> Option<i32> {
    unsafe {
        let s = socket(AF_UNIX, SOCK_SEQPACKET, 0);
        if s == -1 {
            return None;
        }
        {
            let mut sa = sockaddr_un {
                sun_family: AF_UNIX as sa_family_t,
                sun_path: [0; 108],
            };
            let bp: &[c_char] =
                &*(path.as_bytes() as *const [u8] as *const [c_char]);
            let l = 108.min(bp.len());
            sa.sun_path[..l].copy_from_slice(&bp[..l]);
            if sa.sun_path[0] == b'@' as c_char {
                sa.sun_path[0] = b'\x00' as c_char;
            }
            let sa_len = l + size_of::<sa_family_t>();
            let sa_ = &sa as *const libc::sockaddr_un as *const libc::sockaddr;
            let ret = libc::connect(s, sa_, sa_len as socklen_t);
            if ret == -1 {
                close(s);
                return None;
            }
        }
        Some(s)
    }
}
