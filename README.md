# PortScope v1.0

<p align="center">
  <img src="https://i.postimg.cc/3RWbxsst/Screenshot-From-2025-09-15-13-03-14.png" alt="PortScope screenshot" width="700">
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.8%2B-blue.svg"></a>
  <a href="https://github.com/d3bug-1/PortScope/stargazers"><img src="https://img.shields.io/github/stars/d3bug-1/PortScope?style=social"></a>
</p>

**PortScope** — Fast concurrent TCP/UDP port scanner with IPv4/IPv6 support, banner grabbing, and safe defaults.

PortScope is a compact, production-minded Python port scanner designed for authorized network reconnaissance, operational troubleshooting, and developer testing. It combines 
high-concurrency scanning with practical, safety-first features: IPv4/IPv6 resolution, concurrent TCP and best-effort UDP probing, optional banner grabbing for basic service 
fingerprinting, preset port lists, and configurable timeouts and worker counts. The tool is single-file, dependency-free (standard library only), and easy to script into automation 
pipelines.

> ⚠️ **Security & Usage Notice:** PortScope is intended **only** for systems you own or have explicit permission to test. Unauthorized scanning may be illegal and/or violate terms of 
> service.

---

## Key features
- High-concurrency scanning using `ThreadPoolExecutor` with configurable worker count.  - IPv4 and IPv6 address resolution and scanning.  - TCP connect scans with optional banner 
grabbing for service identification.  - Best-effort UDP probing for services that respond to datagrams.  - Flexible port selection: ranges, comma-separated lists, and presets 
(`common`, `top100`, `top1000`).  - Tunable timeouts, retries, and exponential backoff.  - Rate limiting and worker-capping to reduce accidental load on targets and the scanner host.  
- Progress reporting, verbose logging, and graceful KeyboardInterrupt handling.  - Exportable results: JSON and CSV output options for automation and reporting.  - Single-file, 
standard-library implementation for portability and auditability.

---

## Installation

- Clone the repositorty
```bash
git clone https://github.com/d3bug-1/PortScope.git

```
And then:

```bash
$ cd PortScope

```

## Command-line options — full reference

positional: target (hostname or IP)
```bash
python3 scanner.py example.com or 192.0.0.1

```

`--help`, `-h` to show all commands

```bash
python3 scanner.py

```


`--ports`, `-p` PORTS ports to scan (comma-separated and/or ranges)

```bash
python3 scanner.py example.com --ports 22,80,443
python3 scanner.py example.com --ports 1-1024

```


`--preset` {common,top100,top1000} use a predefined port set

```bash
python3 scanner.py 8.8.8.8 --preset common

```


`--timeout`, `-t` TIMEOUT socket connect timeout in seconds (float)

```bash
python3 scanner.py example.com --timeout 0.5

```


`--autoset-timeout` auto-tune timeout using quick sample connects (best-effort)

```bash
python3 scanner.py example.com --autoset-timeout

```


`--workers`, `-w` WORKERS concurrent worker threads (capped by system limits)

```bash
python3 scanner.py example.com --workers 400

```

`--rate RATE` delay (seconds) between task submissions (simple pacing)

```bash
python3 scanner.py example.com --ports 1-1000 --rate 0.01

```


`--retries N` number of attempts per check (default 1)

```bash
python3 scanner.py example.com --ports 80 --retries 3

```


`--backoff S` base backoff seconds for retries (exponential)

```bash
python3 scanner.py example.com --ports 80 --retries 3 --backoff 2

```

 `--grab-banner` attempt to read a small banner after TCP connect

```bash
python3 scanner.py example.com --ports 21,22,80 --grab-banner

```

`--udp` enable UDP probing (best-effort)

```bash
python3 scanner.py example.com --udp --ports 53,123

```

`--tcp` enable TCP scanning (default if neither --tcp nor --udp specified)

```bash
python3 scanner.py example.com --tcp --ports 22,80

```

`--udp-only` scan only UDP ports (implies --udp)

```bash
python3 scanner.py example.com --udp-only --ports 53,161

```


`--tcp-only` scan only TCP ports (implies --tcp)

```bash
python3 scanner.py example.com --tcp-only --ports 1-1024

```


`--ipv6` prefer/allow IPv6 resolution and scanning

```bash
python3 scanner.py [2001:db8::1] --ipv6 --ports 22,80

```


`--show-closed` print closed ports as they are checked (verbose)

```bash
python3 scanner.py example.com --ports 1-200 --show-closed

```
`--verbose`, `-v` verbose mode (progress/debug messages)

```bash
python3 scanner.py example.com --verbose

```


`--no-color` disable ANSI color output (useful for logs)

```bash
python3 scanner.py example.com --no-color

```

`--output`, `-o FILE` save results to a file (.json or .csv). If no ext -> .json appended

```bash
python3 scanner.py example.com --ports 1-500 -o results.json
python3 scanner.py example.com --ports 1-500 -o results.csv
python3 scanner.py example.com --ports 1-500 -o scan_output        # saved as scan_output.json

```

`--preset-show` print available preset port lists and exit

```bash
python3 scanner.py --preset-show

```

`--version` show program version and exit

```bash
python3 scanner.py --version

```


`--max-open-warning N` warn if more than N open ports are found

```bash
python3 scanner.py example.com --max-open-warning 200

```


Combined example (real-world):
aggressive full-TCP scan, banner grabbing, save JSON, moderate rate:

```bash
python3 scanner.py example.com --ports 1-65535 --workers 400 --timeout 0.5 --grab-banner -o example_scan.json --rate 0.005

```
