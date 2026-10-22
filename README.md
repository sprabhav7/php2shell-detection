# php2shell-detections

Non-invasive detector for the PHP2Shell RCE pair: **CVE-2026-109618** and
**CVE-2026-109619**.

## The vulnerabilities

Two critical (CVSS 9.2) unauthenticated remote-code-execution flaws in core PHP,
disclosed 2026-10-21. CVE-2026-109619 is a use-after-free in `longjmp()`
fatal-error handling — leftover global state points to freed memory a later
request on the same worker can reuse — and is tied to `session.upload_progress`.
Both CVEs share the same affected ranges and patches.

| Branch | Affected versions | First fixed |
|--------|-------------------|-------------|
| 8.5 | 8.5.0 – 8.5.11 | 8.5.12 |
| 8.4 | 8.4.0 – 8.4.26 | 8.4.27 |
| 8.3 | 8.3.0 – 8.3.35 | 8.3.36 |
| 8.2 | 8.2.0 – 8.2.34 | 8.2.35 |
| 5.4 – 8.1 | all (end-of-life) | no upstream releases |

## What the detector does

Given a file of targets (IPs, hostnames, or CIDR blocks), it probes a set of
ports, makes a normal `GET` to `/` and `/index.php`, follows up to 3
same-origin redirects, and reads the PHP version the server volunteers — from
`X-Powered-By`, `Server`, a `PHPSESSID` cookie, or any other header that leaks a
`PHP/x.y.z` token. It compares that version against the table above and writes a
ranked report.

It is a detection, **not an exploit**: it only sends well-formed GETs, never
sends malformed input or an exploit payload, never touches the vulnerable code
path, and makes no state-changing request. A status comes from a version banner
— it is an indicator, not confirmation the host is exploitable. Scan only hosts
you are authorized to scan.

Statuses:

| Status | Meaning |
|--------|---------|
| `VULNERABLE` | Reported version is below the fix for its branch. |
| `END OF LIFE` | Branch 5.4–8.1: affected, no upstream release. |
| `POSSIBLY VULNERABLE` | Affected branch but patch level hidden (e.g. `PHP/8.2`); likely, not confirmed — verify. |
| `VERSION UNKNOWN` | PHP present but no usable version (no version shown, major-only, or branch not in the advisories). |
| `PATCHED` | Reported version is at or above the first fixed release. |

## Usage

```bash
pip install -r requirements.txt   # aiohttp

# scan a target file, write the report (default scan_results.txt)
python3 php2shell_detect.py -t hosts.txt

# choose the output file and the ports to probe
python3 php2shell_detect.py -t hosts.txt -o report.txt -p 80,443,8080,8443,8000

# quiet mode: print only hosts with an indicator
python3 php2shell_detect.py -t hosts.txt -q
```

`hosts.txt` is one target per line (`#` comments allowed); CIDR blocks are
expanded, and a block larger than 65,536 addresses is skipped.

**Exit codes:** `0` clean, `2` at least one indicator found (so it can gate CI),
`1` could not write the report, `130` interrupted (partial results saved).
