## TT, The Tunnel
A lightwight, cross-platform, secure and functional tunnel protocol, or tool.

----
### Quick start
#### server

    tt server -k password                       # will listen on 0.0.0.0, ports range: 1024-65535

#### client

    tt client -s [server addr] -k password      # will listen for socks5 connection on 127.0.0.1:1080

----
### Benchmark?
Laptop: i7-8550U(max 4GHz), 16GB LPDDR3 2133 RAM 
	
	# server run:
	tt server -k 1234 &; sudo nc -l -p 80 < /dev/zero

	# client run:
	tt client -s 127.0.0.1 -k 1234 &; curl -x socks5://127.0.0.1:1080 127.0.0.1 >>/dev/null

Result:

```aes-256-gcm```: ~ 300MB/s

```chacha20-poly1305```: ~ 200MB/s

----
### Roadmap / Aims
- [x] Port jumping
    - [x] dynamic TCP port (HOTP)
    - [ ] dynamic UDP port (HOTP)
    - [x] dynamic port lifetime (HOTP)
- [x] Random padding
    - [x] random data at the beginning of payload
    - [x] dynamic length of random data
- [ ] Replay attack proof
	- [ ] use port+counter as AEAD additional data
- [x] Underlying protocol
    - [x] TCP
    - [ ] TCP with fastopen
    - [ ] UDP
- [x] Proxy & tunnels 
    - [x] socks5 proxy(only CONNECT command suppported)
    - [x] TUN support (for Linux
	- [x] UTUN support (for MacOS
	- [ ] [WinTUN](https://www.wintun.net/) support (for Windows
- [x] Encryption
    - [x] chacha20-poly1305
    - [x] aes-256-gcm
- [x] Encryption block size
	- [x] configurable max block size ('--buffer-size', WARNING: less than 1400 will leave a serious traffic pattern)
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
tt-server 0.3.0
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
    -m, --methods <methods>             [default: chacha20-poly1305]
    -r, --port-range <range>            [default: 1024-65535]
        --tun-ip <tun-ip>
```

#### client
```
tt-client 0.3.0
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
    -m, --methods <methods>             [default: chacha20-poly1305]
    -r, --port-range <range>            [default: 1024-65535]
    -s, --server <server>
        --tun-ip <tun-ip>
```

