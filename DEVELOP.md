# Development Guide

A local development setup that lets you build a debug Nginx, compile the module into it, and run it -- all from the project root directory.

> All scripts below **must** be run from the project root.

## Prerequisites

- GCC (or another C compiler)
- Make
- curl
- Python 3 (for the utility scripts)

## 1. Install Nginx

Run the installer script to download, compile, and install a debug-enabled Nginx into `build/nginx/`:

```bash
util/installer
```

This will:

1. Create `vendor/` and `build/` directories.
2. Download the Nginx source tarball (default version: **1.28.2**) into `vendor/`.
3. Configure, compile, and install Nginx with `--with-debug` and `--with-stream` into `build/nginx/`.
4. Symlink `util/nginx.conf` into `build/nginx/conf/nginx.conf`.

> **Note:** This installs Nginx **without** the hunter module -- a clean baseline you can use for comparison.

To change the Nginx version, edit the `NGINX_VERSION` variable at the top of `util/installer` before running it.

To start fresh, remove everything and re-install:

```bash
util/installer clean
util/installer
```

## 2. Compile

Two compile scripts are provided so you can quickly switch between builds with and without the module.

### With the hunter module

```bash
util/compile
```

Configures and builds Nginx with `--add-module` pointing to the project root, then installs into `build/nginx/`.

### Without the hunter module

```bash
util/compile_no_hunter
```

Same as above but without the module -- useful for verifying baseline behavior or isolating issues.

Both scripts build with debug symbols (`-g -O0`) enabled.

## 3. Configure

A ready-to-use configuration file is provided at `util/nginx.conf`. The installer automatically symlinks it, but if you need to copy it manually:

```bash
cp util/nginx.conf build/nginx/conf/nginx.conf
```

Before running, edit the `working_directory` directive to match your project path:

```nginx
working_directory  /absolute/path/to/ngx_hunter_module/build/nginx/dumps;
```

Make sure the target directory exists:

```bash
mkdir -p build/nginx/dumps
```

## 4. Run

Start Nginx (runs in the foreground due to `daemon off;` in the config):

```bash
build/nginx/sbin/nginx
```

Since the config uses `daemon off;`, press `Ctrl+C` in the Nginx terminal to stop it.

## 5. Utility Scripts

All utility scripts live in `util/` and are written in Python 3.

---

### backend.py

A TCP server that the hunter module connects to on worker startup to retrieve an initial list of IPs. Listens on `127.0.0.1:6981` (matching the `hunter_ips_source_host` / `hunter_ips_source_port` directives in the sample config). Sends a set of hardcoded IPs in binary format using the module's wire protocol.

```bash
python util/backend.py
```

Run in test mode to verify the connection and print the IPs that would be sent:

```bash
python util/backend.py test
```

---

### fill_on_start.py

A variant of `backend.py` that sends back a small set of fake IPs when an Nginx worker starts and prints the number of IPs delivered. Same purpose as `backend.py` but with extra debug output.

```bash
python util/fill_on_start.py
```

---

### runtime_feed_simple.py

A TCP client that sends add/remove IP commands to the hunter module's `hunter_ip_operation` endpoint at runtime.

```bash
python util/runtime_feed_simple.py a4 192.168.1.1    # add an IPv4
python util/runtime_feed_simple.py d4 192.168.1.1    # remove an IPv4
python util/runtime_feed_simple.py a6 ::1            # add an IPv6
python util/runtime_feed_simple.py d6 ::1            # remove an IPv6
```

---

### ipo_simulator.py

An async TCP server that implements the **exact same IP operation protocol** as the hunter module itself. Its purpose is to let client developers build and test their IP operation clients against a lightweight simulator without needing a full Nginx + hunter setup.

```bash
python util/ipo_simulator.py
```

The simulator listens on `127.0.0.1:5146`, accepts the same binary protocol used by `hunter_ip_operation`, and prints each parsed operation to stdout.
