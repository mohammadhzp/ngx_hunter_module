# ngx_hunter_module

An Nginx module for **IP-based Web Application Firewall (WAF)** at both layer 4 (TCP/stream) and layer 7 (HTTP). It maintains a shared-memory blacklist of IP addresses using red-black trees and can block or redirect connections in real time. Both IPv4 and IPv6 are supported.

## How It Works

The module stores IP addresses in shared memory backed by a red-black tree for fast lookups. IPs can be loaded from an external TCP backend when Nginx starts and added or removed at runtime through a dedicated TCP endpoint. On every incoming connection, the module checks the client IP against the blacklist and either drops the connection, redirects it to a "blocked" upstream, or passes it through to a "success" upstream.

```
                                  +-----------+
     fill on start (TCP) ------->|           |
                                  |  Shared   |
     runtime add/remove (TCP) -->|  Memory   |
                                  |  (rbtree) |
                                  +-----------+
                                       |
                                       | lookup
                                       v
     Client ----> Nginx stream ----[IP check]----> success upstream
                                       |
                                       +---------> block upstream / drop
```

Either the HTTP module, the stream module, or both can be enabled at build time by editing the `config` file:

```sh
disable_hunter_http="YES"    # set to "NO" to enable the HTTP module
disable_hunter_stream="NO"   # set to "YES" to disable the stream module
```

> HTTP module is in development. do not use it for now.

> On UDP based DDOS attack this module is useless.

## Compatibility

- Nginx >= **1.18.0**
- Tested on recent Linux

## Build

Build as a static or dynamic Nginx module:

```bash
# Static module
./configure --add-module=/path/to/ngx_hunter_module --with-stream

# Dynamic module
./configure --add-dynamic-module=/path/to/ngx_hunter_module --with-stream
```

No external library dependencies are required.

## Directives

### Stream `stream {}` block

| Directive | Default | Description |
|---|---|---|
| `hunter_enabled` | `off` | Master switch. When `off`, every other hunter directive is ignored. |
| `hunter_memory_size` | -- | Shared memory size for the IP store (e.g. `512m`, `1024k`). Minimum 1 MB. |
| `hunter_ips_source_host` | -- | TCP host to connect to on start/reload to retrieve the initial IP list. |
| `hunter_ips_source_port` | -- | TCP port to use with `hunter_ips_source_host`. |
| `hunter_ignore_errors_on_ips_start_fill` | `off` | When `on`, Nginx continues to start even if the IP source backend is unreachable. |

### Stream `server {}` block

| Directive | Default | Description |
|---|---|---|
| `hunter_status` | `on` | Enable or disable the WAF for this server block. |
| `hunter_check_ip` | `on` | Check individual IPs against the blacklist. |
| `hunter_check_range` | `on` | Check IP ranges against the blacklist. |
| `hunter_upstream_success` | -- | Upstream name to proxy to when the IP is **not** blacklisted. |
| `hunter_upstream_block` | -- | Upstream name to proxy to when the IP **is** blacklisted. Required unless `hunter_drop_on_block` is `on`. |
| `hunter_drop_on_block` | `on` | When `on`, immediately drop blacklisted connections instead of proxying to `hunter_upstream_block`. |
| `hunter_ip_operation` | -- | Mark this server block as the runtime IP add/remove endpoint (no arguments). |

### HTTP `http {}` block

| Directive | Default | Description |
|---|---|---|
| `hunter_enabled` | `off` | Master switch for the HTTP module. |
| `hunter_post_read` | `off` | When `on`, run at the post-read phase instead of pre-access. |
| `hunter_memory_size` | -- | Shared memory size (e.g. `3m`). Minimum 1 MB. |
| `hunter_source_host` | -- | TCP host for the IP source backend. |
| `hunter_source_port` | -- | TCP port for the IP source backend. |

### HTTP `location {}` / `server {}` block

| Directive | Default | Description |
|---|---|---|
| `hunter_status` | `on` | Enable or disable the WAF for this location/server. |
| `hunter_check_ip` | `on` | Check individual IPs. |
| `hunter_check_range` | `on` | Check IP ranges. |
| `hunter_ip_operation` | -- | Mark this location as the runtime IP add/remove endpoint (no arguments). |

## Variables

| Variable | Scope | Description |
|---|---|---|
| `$hunter_upstream` | stream | Resolves to the success or block upstream name based on the client IP status. Use as `proxy_pass $hunter_upstream;` when `hunter_drop_on_block` is `off`. |
| `$hunter_ips_count` | stream | Number of IPs currently stored in shared memory. |

## Wire Protocol

The module uses a simple binary protocol over raw TCP for maximum performance.

### IP Feed (startup)

When a worker starts, it connects to the backend defined by `hunter_ips_source_host` / `hunter_ips_source_port`. The backend sends:

```
[4-byte IPv4][4-byte IPv4]...[!!!!][16-byte IPv6][16-byte IPv6]...
```

- IPs are in **binary (network byte order)** format.
- The delimiter `!!!!` (4 bytes) separates IPv4 from IPv6. It must be sent even if there are no IPv4 addresses.
- If no IPs are available, simply close the connection.

### IP Operation (runtime)

To add or remove IPs at runtime, send a raw TCP message to the `hunter_ip_operation` server:

```
[type:2 bytes][binary IP(s)][done]
```

`type` is one of:

| Type | Action |
|---|---|
| `a4` | Add IPv4 |
| `d4` | Remove IPv4 |
| `a6` | Add IPv6 |
| `d6` | Remove IPv6 |

The end marker is the literal string **`done`**. The server responds with the number of successfully processed IPs (or a negative error code).

## Example Configuration

```nginx
stream {
    upstream success {
        server 127.0.0.1:8891;
    }

    upstream block {
        server 127.0.0.1:8890;
    }

    hunter_enabled                        on;
    hunter_memory_size                    512m;
    hunter_ips_source_host                "127.0.0.1";
    hunter_ips_source_port                6981;
    hunter_ignore_errors_on_ips_start_fill on;

    server {  # public-facing
        listen 8892 backlog=512;
        listen [::]:8892;

        hunter_upstream_success "success";
        hunter_upstream_block   "block";
        hunter_drop_on_block    off;

        proxy_pass $hunter_upstream;
    }

    server {  # IP count endpoint
        listen 8893;
        hunter_status off;
        return $hunter_ips_count;
    }

    server {  # runtime IP management (internal)
        listen 8889;
        hunter_status off;
        hunter_ip_operation;
    }
}
```

With this configuration, every TCP connection to port **8892** is checked against the blacklist. Allowed connections are proxied to `success` (port 8891); blocked connections are proxied to `block` (port 8890). Port **8889** accepts runtime add/remove IP commands.

## Development

See [DEVELOP.md](DEVELOP.md) for instructions on setting up a local debug Nginx build, compiling with or without the module, and running the utility scripts.
