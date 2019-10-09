## TT, The Tunnel
A lightwight, cross-platform, secure and functional tunnel protocol, or tool.

----
### Quick start
#### for server

    tt server -k password                       # will listen on 0.0.0.0, ports range: 1024-65535

#### for client

    tt client -s [server addr] -k password      # will listen for socks5 connection on 127.0.0.1:1080
    
----
### Roadmap / Aims
- [x] Underlying protocol
    - [x] TCP 
    - [ ] TCP with fastopen
    - [ ] UDP
- [ ] Dynamic port
    - [x] dynamic TCP port (HOTP)
    - [ ] dynamic UDP port (HOTP)
    - [x] dynamic port lifetime (HOTP)
	- [ ] **keep socks5 connection alive on server port change**
- [x] Random padding
    - [x] random data at the beginning of payload
    - [x] dynamic length of random data
- [x] Proxy & tunnels 
    - [x] socks5 proxy (use merino for now, need to implement one inside tt)
    - [ ] TUN/TAP support
- [x] Encryption
    - [x] chacha20-poly1305
    - [ ] aes-256-gcm
- [x] Encryption block size
	- [x] configurable max block size ('--buffer-size' as in options. Notice: less than 1400 will leave a serious traffic pattern)
- [x] Binary tool
    - [x] single binary serves as both server and client, with brief options
    - [ ] **daemon mode support**
- [ ] Hook API 
    - [ ] encode/decode hook api (consider eBPF)
- [ ] Fake traffic
    - [ ] fake http/https server
    - [ ] fake http/https traffic from client
- [ ] Multiple servers
    - [ ] support multiple servers
    - [ ] support for setting different weight for each server

----
### Full Usage 
#### server
```
tt-server 0.1.5
TT, The Tunnel, server side

USAGE:
    tt server [OPTIONS] --key <key>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --buffer-size <buffer-size>     [default: 4096]
    -k, --key <key>
    -l, --listen <listen-addr>          [default: 0.0.0.0]
    -r, --port-range <range>            [default: 1024-65535]
```

#### client
```
tt-client 0.1.5
TT, The Tunnel, client side

USAGE:
    tt client [OPTIONS] --key <key> --server <server>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --buffer-size <buffer-size>     [default: 4096]
    -k, --key <key>
    -l, --listen <listen-addr>          [default: 127.0.0.1:1080]
    -r, --port-range <range>            [default: 1024-65535]
    -s, --server <server>

```

