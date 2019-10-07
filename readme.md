TT, The Tunnel
-- 

### server
```
tt-server 0.1.0
TT, The Tunnel, server side

USAGE:
    tt server [OPTIONS] --key <key>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -k, --key <key>               
    -l, --listen <listen-addr>     [default: 0.0.0.0]
    -m, --mtu <mtu>                [default: 500]
    -r, --port-range <range>       [default: 1024-65535]
```

### client
```
tt-client 0.1.0
TT, The Tunnel, client side

USAGE:
    tt client [OPTIONS] --key <key> --server <server>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -k, --key <key>               
    -l, --listen <listen-addr>     [default: 127.0.0.1:1080]
    -m, --mtu <mtu>                [default: 500]
    -r, --port-range <range>       [default: 1024-65535]
    -s, --server <server>
```
