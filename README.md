# PortScope v1.0

**PortScope** — Fast concurrent TCP/UDP port scanner with IPv4/IPv6 support, banner grabbing, and safe defaults.

PortScope is a compact, production-minded Python port scanner designed for authorized network reconnaissance, operational troubleshooting, and developer testing. It combines high-concurrency scanning with practical, safety-first features: IPv4/IPv6 resolution, concurrent TCP and best-effort UDP probing, optional banner grabbing for basic service fingerprinting, preset port lists, and configurable timeouts and worker counts. The tool is single-file, dependency-free (standard library only), and easy to script into automation pipelines.

> ⚠️ **Security & Usage Notice:** PortScope is intended **only** for systems you own or have explicit permission to test. Unauthorized scanning may be illegal and/or violate terms of service.

---

## 🔥 Key features
- High-concurrency scanning using `ThreadPoolExecutor` with configurable worker count.  
- IPv4 and IPv6 address resolution and scanning.  
- TCP connect scans with optional banner grabbing for service identification.  
- Best-effort UDP probing for services that respond to datagrams.  
- Flexible port selection: ranges, comma-separated lists, and presets (`common`, `top100`, `top1000`).  
- Tunable timeouts, retries, and exponential backoff.  
- Rate limiting and worker-capping to reduce accidental load on targets and the scanner host.  
- Progress reporting, verbose logging, and graceful KeyboardInterrupt handling.  
- Exportable results: JSON and CSV output options for automation and reporting.  
- Single-file, standard-library implementation for portability and auditability.

---

## 📦 Installation

Clone the repository:

```bash
git clone https://github.com/d3bug-1/PortScope.git
cd PortScope


| Option                             | Description                                                                                           | Example                                                        |
| ---------------------------------- | ----------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| `target` (positional)              | Target hostname or IP address to scan.                                                                | `python3 scanner.py example.com`                               |
| `--ports, -p PORTS`                | Ports to scan. Accepts comma lists and ranges (e.g. `22,80,443` or `1-1024`).                         | `python3 scanner.py example.com --ports 22,80,443`             |
| `--preset {common,top100,top1000}` | Use a predefined port set.                                                                            | `python3 scanner.py 8.8.8.8 --preset common`                   |
| `--timeout, -t TIMEOUT`            | Socket connect timeout in seconds (float). Default: `1.0`.                                            | `python3 scanner.py example.com --timeout 0.5`                 |
| `--autoset-timeout`                | Auto-tune timeout based on quick sample connects (best-effort).                                       | `python3 scanner.py example.com --autoset-timeout`             |
| `--workers, -w WORKERS`            | Number of concurrent worker threads (capped by system limits). Default: `200`.                        | `python3 scanner.py target.com --workers 400`                  |
| `--rate RATE`                      | Delay (seconds) between task submissions (simple rate limiting).                                      | `python3 scanner.py target.com --ports 1-1000 --rate 0.01`     |
| `--retries N`                      | Number of attempts per check (default `1`).                                                           | `python3 scanner.py example.com --ports 80 --retries 3`        |
| `--backoff S`                      | Base backoff (seconds) for retries — exponential backoff: `S * 2^(attempt-1)`.                        | `python3 scanner.py example.com --retries 3 --backoff 2`       |
| `--grab-banner`                    | Attempt to read a small banner from open TCP services (HTTP/SSH/etc.).                                | `python3 scanner.py example.com --ports 22,80 --grab-banner`   |
| `--udp`                            | Enable UDP probing (best-effort; many UDP services do not respond).                                   | `python3 scanner.py example.com --udp --ports 53,123`          |
| `--tcp`                            | Enable TCP scanning. If neither `--tcp` nor `--udp` specified, TCP is enabled by default.             | `python3 scanner.py example.com --tcp --ports 22,80`           |
| `--udp-only`                       | Scan only UDP ports (implies `--udp`).                                                                | `python3 scanner.py example.com --udp-only --ports 53,161`     |
| `--tcp-only`                       | Scan only TCP ports (implies `--tcp`).                                                                | `python3 scanner.py example.com --tcp-only --ports 1-1024`     |
| `--ipv6`                           | Prefer/allow IPv6 address resolution and scanning for the target.                                     | `python3 scanner.py [2001:db8::1] --ipv6 --ports 22,80`        |
| `--show-closed`                    | Print closed ports as they are checked (very verbose).                                                | `python3 scanner.py example.com --ports 1-200 --show-closed`   |
| `--verbose, -v`                    | Verbose mode — extra progress and debug messages.                                                     | `python3 scanner.py example.com --verbose`                     |
| `--no-color`                       | Disable ANSI colored output (useful for logs).                                                        | `python3 scanner.py example.com --no-color`                    |
| `--output, -o FILE`                | Save results to a file. Supports `.json` and `.csv`. If no recognized extension, `.json` is appended. | `python3 scanner.py example.com --ports 1-500 -o results.json` |
| `--preset-show`                    | Print available preset port lists and exit.                                                           | `python3 scanner.py --preset-show`                             |
| `--version`                        | Show program version and exit.                                                                        | `python3 scanner.py --version`                                 |
| `--max-open-warning N`             | Warn if more than `N` open ports are found (safety threshold).                                        | `python3 scanner.py example.com --max-open-warning 200`        |


