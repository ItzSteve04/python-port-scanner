# Verification record

Version **1.0.1**. Local checks below were rerun on **2026-10-27** using
**CPython 3.12.14 on Linux**. Windows results came from a user-provided terminal
transcript; they were not executed in this review environment.

## Results

| Check | Result |
| --- | --- |
| Unit and localhost integration tests against source | **89 passed; 0 skipped** |
| Combined statement/branch coverage | **98%**; configured minimum 85% |
| Ruff lint and formatting checks | Passed |
| Strict mypy checks, targeting Python 3.11 | Passed; 11 source modules |
| Source distribution and wheel build | Passed with `--no-isolation` using installed build tools |
| Wheel installation in a fresh virtual environment | Passed with `--no-index --no-deps` |
| Complete suite against the installed wheel | **89 passed; 0 skipped** |
| Installed CLI help and version | Passed; version 1.0.1 |
| IPv4 and IPv6 loopback, banner limits, rate limiting, and exports | Passed in the integration suite |
| POSIX subprocess SIGINT and partial JSON export | Passed; exit 130 |
| Windows automated tests, user-reported | **88 passed; 1 expected skip; 0 failures**, 5.636 seconds |
| Windows manual Ctrl+C handling | Not verified |
| README screenshots and example reports | Inspected; localhost data and fictional demo greeting |

The tests combine deterministic mocked failures with real loopback sockets. No
third-party target was scanned. A passing test run establishes the listed scanner
behaviour under these conditions, not the security of any scanned system.

The non-listening-port integration test accepts either refusal or timeout because
operating-system response timing varies. Separate regression tests require Winsock
10061 to remain `closed` and 10035 to remain `timed_out`. A banner timeout does not
change an already successful TCP connection from `open`.

## Reproduce

After installing the development extras in a virtual environment:

```bash
python -m pip install -e ".[dev]"
python -m coverage run -m unittest discover -s tests -v
python -m coverage report
python -m ruff check .
python -m ruff format --check .
python -m mypy
python -m build
```

For the localhost demo, run `python scripts/local_demo.py`. It rewrites the example
reports and terminal transcripts; see `examples/README.md` before regenerating images.

## Public-repository checks

- Extended `.gitignore` and checked 44 representative local/generated paths are
  ignored, while 22 representative source/documentation paths remain included.
- Excluded virtual environments, bytecode, build output, package metadata, tool
  caches, and local Git metadata from the publication ZIP.
- Verified all relative Markdown file/image links resolve.
- Updated `MANIFEST.in` to include `RESPONSIBLE_USE.md` and `.gitignore`, and removed
  references to the deleted contribution and security-policy files.
- Checked project text for common credential patterns; no obvious matches were found.
  This is not a guarantee that every possible secret format can be detected.
- Confirmed scanner source and service data are unchanged from the uploaded version.

## Limits and pending checks

- GitHub Actions is configured for Python 3.11-3.14 on Linux, plus 3.11 and 3.14 on
  Windows and macOS. The hosted workflow still needs its first run after publication.
  Local Python 3.12 checks and the reported Windows run do not cover the whole matrix.
- Manual Windows Ctrl+C delivery remains untested. The POSIX subprocess signal test
  intentionally skips on Windows. IPv6 tests skip when loopback IPv6 is unavailable.
- No production network, external DNS outage, or routed firewall was tested.
  Failure cases have mocked coverage, and DNS timeout behaviour follows the OS resolver.
