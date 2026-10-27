# Export format version 1.0

See the actual loopback reports in `examples/`. All port observations are exported even when
the terminal table shows only open ports. Port order is ascending.

## JSON

| Field | Meaning |
| --- | --- |
| `schema_version` | Export contract version, currently `1.0` |
| `scanner_version` | Package version |
| `target` | Normalized input, selected address, IP family, IPv6 scope, all resolved addresses |
| `started_at`, `finished_at` | UTC ISO 8601 timestamps, starting after resolution |
| `duration_seconds` | Monotonic elapsed scanning time, excluding resolution and exports |
| `interrupted` | Cancellation was requested |
| `configuration` | Validated options, including requested ports and authorization assertion |
| `summary` | Requested, completed, unscanned and per-state counts |
| `unscanned_ports` | Ports without a completed observation; never implicitly closed |
| `results` | Every completed port observation |

Each result contains `port`, `state`, `service`, `service_source`, `connect_ms`, `banner`, and
`error`. `banner` is null when disabled or when the port was not open. Otherwise it contains:

- `status`: `received`, `timeout`, `empty`, `error`, or `cancelled`.
- `text`: UTF-8 decoded with replacement, backslashes doubled and controls escaped.
- `bytes_received`: Actual bytes received, before decoding and escaping.
- `at_limit`: The receive returned exactly the configured byte cap; more data is possible.

`connect_ms` includes local socket creation and connection work, excludes banner collection,
and is rounded to three decimal places. Error descriptions are diagnostic and platform dependent;
use `state` for automation. Counts satisfy `completed + unscanned == requested`. A connection
already in progress when cancelled may still produce an observation.

## CSV

CSV has a header and one row per completed observation. The first ten columns repeat scan
metadata, including `interrupted`, `requested`, `completed`, and `unscanned`. The remaining
columns flatten the port and banner observations. An empty scan has one metadata-only row
with an empty `port`; it does not represent an extra observation. CSV does not include the
full requested/unscanned port lists or all configuration fields; use JSON for complete metadata.

Fields use standard CSV quoting. Strings beginning with `=`, `+`, `-`, or `@` after leading
whitespace, or beginning with tab/CR/LF, are prefixed with an apostrophe to neutralize common
spreadsheet formula interpretation. This changes those CSV cell values; use JSON when the
escaped string must be retained exactly. Neither format stores raw binary banner data.

Each destination is written to a private temporary file in the same directory, flushed, and
replaced with `os.replace`. The parent must already exist. Replacement is atomic per file,
not a transaction spanning JSON and CSV. Existing files are overwritten. The scanner does
not guarantee durability across every filesystem or power-loss scenario.
