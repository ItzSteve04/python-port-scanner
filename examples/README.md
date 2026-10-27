# Localhost example data

`local-scan.json`, `local-scan.csv`, and `terminal-session.txt` come from an actual execution
of `python scripts/local_demo.py`. It starts ephemeral greeting and silent TCP services on
`127.0.0.1`, plus a reserved non-listening port, then invokes the installed scanner CLI.
The SSH-shaped greeting is fictional text emitted by the demo, not a real SSH server.

`cli-help.txt` is captured from `port-scanner --help`. The PNG images in `docs/assets/` render
these text captures with Pillow. Recreate them with:

```bash
python scripts/local_demo.py
python -m pip install Pillow
python scripts/render_screenshots.py --font /path/to/monospace-font.ttf
```

Port numbers, timestamps, timing values, and operating-system service fallback names vary.
An `unknown` service hint on an ephemeral port is expected. All addresses are loopback;
no organization or third-party target data is included.

The reserved non-listening port can report `closed` or `timed_out` on different systems.
On Windows, a short connect timeout may produce Winsock 10035 before a refusal is reported.
The silent service's `banner [timeout]` is also expected; its successful TCP connection
still makes that port `open`.
