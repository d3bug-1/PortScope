#!/usr/bin/env python3
"""
Advanced port scanner (TCP/UDP) v1.0 — by D3bug (enhanced)
"""

from __future__ import annotations
import argparse
import socket
import sys
import time
import json
import csv
import os
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock, Event
from typing import List, Tuple, Optional

# ASCII banner
ASCII_BANNER = r"""
    ____             __     _____                                     _    _____
   / __ \____  _____/ /_   / ___/_________ _____  ____  ___  _____   | |  / <  /
  / /_/ / __ \/ ___/ __/   \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/   | | / // / 
 / ____/ /_/ / /  / /_    ___/ / /__/ /_/ / / / / / / /  __/ /       | |/ // /  
/_/    \____/_/   \__/   /____/\___/\__,_/_/ /_/_/ /_/\___/_/        |___//_/    

   	advanced port scanner — TCP/UDP (IPv4/IPv6) by D3bug.
 -----------------------------------------------------------------------------
    NOTE: Only scan systems you are authorized to test. Unauthorized scanning
 		may be illegal or violate terms of service.
 -----------------------------------------------------------------------------
"""

if len(sys.argv) == 1:
    print(ASCII_BANNER)
    sys.exit(0)

# Presets
PRESETS = {
    "common": "20,21,22,23,25,53,67,68,80,110,111,123,135,137-139,143,161,389,443,445,3306,3389,5900,8080",
    "top100": "1-1024,1433,1521,2049,2375,2376,27017,5000,5432,5900,8000-8100,9000-9100",
    "top1000": "1-2000,3306,3389,5000,5432,5900,8000-8100,9000-9100",
}

# Custom help
CUSTOM_HELP = """
port scanner v1.0 — Fast concurrent TCP/UDP port scanner (IPv4/IPv6) by D3bug.

positional arguments:
  target                Target hostname or IP address to scan

options:
  -h, --help            show this help message and exit (this custom help hides the argparse 'usage:' line)
  --ports, -p PORTS     Ports to scan: range(s) or list separated by commas.
                        Examples: '1-1024', '22,80,443'. Default: 1-1024
  --preset              Use a preset port set: common, top100, top1000
  --timeout, -t TIMEOUT Socket connect timeout in seconds (float). Default: 1.0
  --autoset-timeout     Auto-tune timeout based on sample connects (best-effort)
  --workers, -w WORKERS Number of concurrent worker threads. Default: 200
  --show-closed         Print closed ports as they are checked (can be verbose)
  --verbose, -v         Verbose mode: prints progress / debug messages
  --version             Show program name and version and exit
  --output, -o FILE     Write results to a file (.json or .csv recommended)
  --rate RATE           Delay (seconds) between task submissions (rate-limiting)
  --retries N           Number of attempts per check (default 1)
  --backoff S           Base backoff (seconds) for retries (exponential)
  --grab-banner         Attempt to read a small banner after TCP connect
  --udp                 Enable UDP probing (best-effort)
  --tcp                 Enable TCP scanning (default if neither --tcp nor --udp provided)
  --udp-only            Scan only UDP ports (implies --udp)
  --tcp-only            Scan only TCP ports (implies --tcp)
  --ipv6                Prefer/respect IPv6 address when resolving target
  --no-color            Disable ANSI color output
  --preset-show         Show available presets and exit
  --max-open-warning N  Warn if more than N open ports are found (safety)

Examples:
  python3 scanner.py example.com
  python3 scanner.py example.com --ports 1-1024 --timeout 0.5 --workers 200
  python3 scanner.py example.com --preset common --grab-banner --output result.json
"""

# Utilities
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def parse_ports(ports_str: str) -> List[int]:
    ports = set()
    for part in ports_str.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            try:
                start_str, end_str = part.split('-', 1)
                start = int(start_str); end = int(end_str)
            except ValueError:
                raise ValueError("invalid port range in --ports")
            if start > end:
                start, end = end, start
            start = max(1, start); end = min(65535, end)
            ports.update(range(start, end + 1))
        else:
            try:
                p = int(part)
            except ValueError:
                raise ValueError("invalid port value in --ports")
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)

def resolve_target(target: str, prefer_ipv6: bool=False) -> List[Tuple]:
    try:
        family = socket.AF_UNSPEC
        infos = socket.getaddrinfo(target, None, family, socket.SOCK_STREAM, 0, 0)
        if prefer_ipv6:
            infos.sort(key=lambda x: 0 if x[0] == socket.AF_INET6 else 1)
        else:
            infos.sort(key=lambda x: 0 if x[0] == socket.AF_INET else 1)
        return infos
    except socket.gaierror as e:
        raise RuntimeError(f"Hostname resolution failed: {e}")

def human_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

#  Socket helper
def tcp_connect_and_banner(sockaddr, port, timeout, grab_banner=False, banner_len=1024, probe_bytes: Optional[bytes]=None):
    family, addr = sockaddr
    s = None
    try:
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((addr, port))
        banner = None
        if grab_banner:
            if probe_bytes:
                try:
                    s.sendall(probe_bytes)
                except Exception:
                    pass
            try:
                s.settimeout(min(1.0, timeout))
                data = s.recv(banner_len)
                if data:
                    banner = data.decode('utf-8', errors='replace').strip()
            except Exception:
                banner = None
        s.close()
        return True, banner, None
    except Exception as e:
        if s:
            try:
                s.close()
            except Exception:
                pass
        return False, None, str(e)

def udp_probe(sockaddr, port, timeout, payload: Optional[bytes]=b''):
    family, addr = sockaddr
    s = None
    try:
        s = socket.socket(family, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(payload, (addr, port))
        except Exception as e:
            return False, f"send_error:{e}"
        try:
            data, _ = s.recvfrom(2048)
            if data:
                try:
                    d = data.decode('utf-8', errors='replace').strip()
                except Exception:
                    d = repr(data)
                s.close()
                return True, f"resp:{d}"
            else:
                s.close()
                return True, "no-data"
        except socket.timeout:
            s.close()
            return False, "no-reply"
        except Exception as e:
            s.close()
            return False, f"recv_error:{e}"
    except Exception as e:
        if s:
            try:
                s.close()
            except Exception:
                pass
        return False, str(e)

# Scanner class
class Scanner:
    def __init__(self, args):
        self.args = args
        self.lock = Lock()
        self.completed = 0
        self.open_ports = []
        self.stop_event = Event()
        self.logger = logging.getLogger("scanner")
        self.addr_infos = []
        self.target_ip_display = None

    def prepare(self):
        infos = resolve_target(self.args['target'], prefer_ipv6=self.args.get('ipv6', False))
        seen = set()
        addr_list = []
        for info in infos:
            fam = info[0]
            sockaddr = info[4]
            addr = sockaddr[0]
            if (fam, addr) not in seen:
                seen.add((fam, addr))
                addr_list.append((fam, addr))
        if not addr_list:
            raise RuntimeError("No addresses resolved for target.")
        self.addr_infos = addr_list
        self.target_ip_display = addr_list[0][1]

        if self.args.get('preset'):
            preset_val = PRESETS.get(self.args['preset'])
            if not preset_val:
                raise RuntimeError(f"Unknown preset: {self.args['preset']}")
            ports_str = preset_val
        else:
            ports_str = self.args.get('ports', "1-1024")
        ports = parse_ports(ports_str)
        if not ports:
            raise RuntimeError("No valid ports to scan.")
        self.ports = ports

        self.rate = float(self.args.get('rate', 0.0))
        requested_workers = int(self.args.get('workers', 200))
        try:
            fd_soft, fd_hard = os.getrlimit(os.RLIMIT_NOFILE)
            safe_workers = max(10, min(requested_workers, max(50, fd_soft // 4)))
        except Exception:
            safe_workers = min(requested_workers, 1000)
        if requested_workers > safe_workers:
            self.logger.warning(f"Requested workers={requested_workers} high for system limits. Capping to {safe_workers}.")
            self.args['workers'] = safe_workers

    def run(self):
        start = time.time()
        timeout = float(self.args.get('timeout', 1.0))
        if self.args.get('autoset_timeout') and self.args.get('tcp'):
            sample_ports = [80, 443, 22]
            sample_ports = [p for p in sample_ports if p in self.ports]
            if sample_ports:
                timings = []
                for p in sample_ports[:3]:
                    try:
                        fam, addr = self.addr_infos[0]
                        t0 = time.time()
                        s = socket.socket(fam, socket.SOCK_STREAM)
                        s.settimeout(0.5)
                        try:
                            s.connect((addr, p))
                            s.close()
                            timings.append(time.time() - t0)
                        except Exception:
                            timings.append(time.time() - t0)
                    except Exception:
                        continue
                if timings:
                    avg = sum(timings) / len(timings)
                    timeout = max(timeout, min(5.0, max(0.2, avg * 3.0)))
                    self.logger.info(f"Auto-tuned timeout to {timeout:.2f}s based on samples.")

        self._print_header(timeout)

        tasks = []
        if self.args.get('tcp'):
            for p in self.ports:
                tasks.append(("tcp", p))
        if self.args.get('udp'):
            for p in self.ports:
                tasks.append(("udp", p))

        self.total_tasks = len(tasks)
        workers = int(self.args.get('workers', 200))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            future_to_task = {}
            try:
                for proto, port in tasks:
                    if self.stop_event.is_set():
                        break
                    if self.rate > 0:
                        time.sleep(self.rate)
                    fam, addr = self.addr_infos[0]
                    if proto == "tcp":
                        future = ex.submit(self._tcp_task, (fam, addr), port, timeout)
                    else:
                        future = ex.submit(self._udp_task, (fam, addr), port, timeout)
                    future_to_task[future] = (proto, port)

                for f in as_completed(future_to_task):
                    if self.stop_event.is_set():
                        break
                    proto, port = future_to_task[f]
                    try:
                        ok, info = f.result()
                    except KeyboardInterrupt:
                        self.stop_event.set()
                        break
                    except Exception as e:
                        self.logger.debug(f"Worker exception for {proto}/{port}: {e}")
                        ok, info = False, f"error:{e}"
                    with self.lock:
                        self.completed += 1
                        if ok:
                            self.open_ports.append((proto, port, info))
                            self._print_open(proto, port, info)
                        else:
                            if self.args.get('show_closed') or self.args.get('verbose'):
                                self._print_closed(proto, port, info)
                        if self.completed % max(1, int(self.total_tasks / 50)) == 0 or self.completed == self.total_tasks:
                            pct = (self.completed / self.total_tasks) * 100
                            print(f"[=] Progress: {self.completed}/{self.total_tasks} ({pct:.1f}%)")
            except KeyboardInterrupt:
                self.logger.warning("Scan cancelled by user (KeyboardInterrupt). Attempting graceful shutdown...")
                self.stop_event.set()
            finally:
                self._print_footer(start)
                try:
                    self._maybe_save_results()
                except Exception as e:
                    self.logger.error(f"Error saving results: {e}")

    def _tcp_task(self, sockaddr, port, timeout):
        attempts = int(self.args.get('retries', 1))
        backoff = float(self.args.get('backoff', 0.0))
        grab = bool(self.args.get('grab_banner', False))
        probe = None
        if grab and port in (80, 8080, 8000, 443):
            try:
                probe = b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % self.args['target'].encode('idna', errors='ignore')
            except Exception:
                probe = b"HEAD / HTTP/1.0\r\n\r\n"
        for attempt in range(1, attempts + 1):
            if self.stop_event.is_set():
                return False, "stopped"
            ok, banner, err = tcp_connect_and_banner(sockaddr, port, timeout, grab_banner=grab, banner_len=1024, probe_bytes=probe)
            if ok:
                return True, banner or "open"
            if attempt < attempts:
                time.sleep(backoff * (2 ** (attempt - 1)))
        return False, err or "closed"

    def _udp_task(self, sockaddr, port, timeout):
        attempts = int(self.args.get('retries', 1))
        backoff = float(self.args.get('backoff', 0.0))
        payload = b''
        if port == 53:
            payload = b'\x00'
        for attempt in range(1, attempts + 1):
            if self.stop_event.is_set():
                return False, "stopped"
            ok, info = udp_probe(sockaddr, port, timeout, payload=payload)
            if ok:
                return True, info
            if attempt < attempts:
                time.sleep(backoff * (2 ** (attempt - 1)))
        return False, info

    def _color(self, s, kind):
        if not self.args.get('color', True):
            return s
        colors = {
            'info': '\033[94m',
            'open': '\033[92m',
            'closed': '\033[90m',
            'warn': '\033[93m',
            'err': '\033[91m',
            'reset': '\033[0m',
        }
        return f"{colors.get(kind,'')}{s}{colors['reset']}"

    def _print_header(self, timeout):
        print("-" * 71)
        print(f"Started: {human_time()}")
        print(f"Target: {self.args['target']} ({self.target_ip_display})")
        try:
            rdn = socket.gethostbyaddr(self.target_ip_display)[0]
            print(f"Reverse DNS: {rdn}")
        except Exception:
            pass
        print(f"Ports to scan: {len(self.ports)} (example: {self.ports[:6]}{'...' if len(self.ports)>6 else ''})")
        proto_list = []
        if self.args.get('tcp'):
            proto_list.append("TCP")
        if self.args.get('udp'):
            proto_list.append("UDP")
        print(f"Protocols: {', '.join(proto_list)} | Timeout: {timeout}s | Workers: {self.args.get('workers')}")
        if self.args.get('grab_banner'):
            print("Banner grabbing: enabled")
        if self.args.get('preset'):
            print(f"Preset: {self.args.get('preset')}")
        print("-" * 71)

    def _print_open(self, proto, port, info):
        tag = f"[+] {proto.upper()} {port} open"
        if info:
            tag += f" — {info}"
        print(self._color(tag, 'open'))

    def _print_closed(self, proto, port, info):
        tag = f"[-] {proto.upper()} {port} closed"
        if info:
            tag += f" ({info})"
        print(self._color(tag, 'closed'))

    def _print_footer(self, start_time):
        print("-" * 71)
        print("Scan finished:", human_time())
        duration = time.time() - start_time
        print(f"Duration: {duration:.2f}s | Total checked: {self.completed}")
        if self.open_ports:
            print(self._color("Open ports:", 'info'), ", ".join(f"{p[0]}/{p[1]}" + (f" ({p[2]})" if p[2] else "") for p in sorted(self.open_ports, key=lambda x:(x[0],x[1]))))
        else:
            print("No open ports found (or none reported).")
        print("-" * 71)

    def _maybe_save_results(self):
        out = self.args.get('output')
        if not out:
            return
        out = os.path.expanduser(out)
        data = {
            "target": self.args['target'],
            "target_ip": self.target_ip_display,
            "timestamp": human_time(),
            "scan_params": {
                "ports_count": len(self.ports),
                "timeout": self.args.get('timeout'),
                "workers": self.args.get('workers'),
                "protocols": ("tcp","udp") if self.args.get('tcp') and self.args.get('udp') else ("tcp",) if self.args.get('tcp') else ("udp",),
            },
            "open_ports": [{"proto": p[0], "port": p[1], "info": p[2]} for p in self.open_ports]
        }
        if out.lower().endswith(".json"):
            with open(out, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
            print(f"[+] Results written to {out}")
        elif out.lower().endswith(".csv"):
            with open(out, "w", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow(["target", "target_ip", "timestamp", "proto", "port", "info"])
                for entry in data['open_ports']:
                    writer.writerow([data['target'], data['target_ip'], data['timestamp'], entry['proto'], entry['port'], entry['info']])
            print(f"[+] Results written to {out}")
        else:
            with open(out + ".json", "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
            print(f"[+] Results written to {out}.json (defaulted to JSON)")

#  CLI parsing
def build_args_from_argv():
    parser = argparse.ArgumentParser(
        prog="scanner.py",
        description="Fast concurrent TCP/UDP port scanner (IPv4/IPv6).",
        add_help=False
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument("--ports", "-p", default="1-1024",
                        help="Ports to scan, e.g. '1-1024' or '22,80,443' (ignored when --preset used)")
    parser.add_argument("--preset", choices=list(PRESETS.keys()), help="Use a preset port list (common, top100, top1000)")
    parser.add_argument("--timeout", "-t", type=float, default=1.0,
                        help="Socket connect timeout in seconds (float). Default: 1.0")
    parser.add_argument("--autoset-timeout", action="store_true",
                        help="Auto-tune timeout based on sample connects (best-effort)")
    parser.add_argument("--workers", "-w", type=int, default=200,
                        help="Number of concurrent worker threads. Will be capped based on system limits.")
    parser.add_argument("--show-closed", action="store_true",
                        help="Print closed ports (can be very verbose)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose mode (debug logging / more info)")
    parser.add_argument("--version", action="store_true", help="Show program name and version")
    parser.add_argument("--output", "-o", help="Write results to a file (use .json or .csv)")
    parser.add_argument("--rate", type=float, default=0.0, help="Delay (seconds) between task submissions (rate-limiting)")
    parser.add_argument("--retries", type=int, default=1, help="Number of attempts per check (default 1)")
    parser.add_argument("--backoff", type=float, default=0.0, help="Base backoff (seconds) for retries (exponential)")
    parser.add_argument("--grab-banner", action="store_true", help="Attempt to read a small banner after TCP connect")
    parser.add_argument("--udp", action="store_true", help="Enable UDP probing (best-effort)")
    parser.add_argument("--tcp", action="store_true", help="Enable TCP scanning (default if neither --tcp nor --udp provided)")
    parser.add_argument("--udp-only", action="store_true", help="Scan only UDP ports (implies --udp)")
    parser.add_argument("--tcp-only", action="store_true", help="Scan only TCP ports (implies --tcp)")
    parser.add_argument("--ipv6", action="store_true", help="Prefer IPv6 address when resolving target")
    parser.add_argument("--no-color", dest="color", action="store_false", help="Disable ANSI color output")
    parser.add_argument("--preset-show", action="store_true", help="Show available presets and exit")
    parser.add_argument("--max-open-warning", type=int, default=500, help="Warn if too many open ports found (safety)")
    parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    return vars(parser.parse_args())

def main():
    if '-h' in sys.argv or '--help' in sys.argv:
        print(CUSTOM_HELP.strip())
        return

    try:
        args = build_args_from_argv()
    except SystemExit:
        return

    if args.get('preset_show'):
        print("Available presets:")
        for k,v in PRESETS.items():
            print(f"  {k}: {v}")
        return

    if args.get('version'):
        print("advanced port scanner v1.0")
        return

    if not args.get('tcp') and not args.get('udp'):
        args['tcp'] = True

    if args.get('udp_only'):
        args['udp'] = True
        args['tcp'] = False
    if args.get('tcp_only'):
        args['tcp'] = True
        args['udp'] = False

    level = logging.DEBUG if args.get('verbose') else logging.INFO
    logging.basicConfig(format="%(asctime)s %(levelname)s: %(message)s", level=level)
    logger = logging.getLogger("scanner")
    logger.info("Starting scan (you must have permission to scan the target).")

    scanner = Scanner(args)
    try:
        scanner.prepare()
    except Exception as e:
        eprint(f"ERROR: {e}")
        sys.exit(1)

    try:
        scanner.run()
    except KeyboardInterrupt:
        logger.warning("Stopped by user (KeyboardInterrupt). Attempting to save partial results...")
        scanner.stop_event.set()
        try:
            scanner._maybe_save_results()
        except Exception:
            pass
        sys.exit(1)
    except Exception as e:
        eprint(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

