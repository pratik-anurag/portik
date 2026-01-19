# Testing portik — step-by-step examples

This document explains how to exercise the main features of `portik` locally, with concrete commands and expected outputs. Run these steps from the repository root.

Prerequisites
- Go (recommended: an up-to-date arm64 Homebrew install) or use `/opt/homebrew/bin/go` when building on Apple Silicon.
- On macOS: `lsof` and `ps` in PATH.
- Optional: `docker` in PATH for Docker mapping tests.

Build

Build using the Homebrew Go (recommended on macOS Apple Silicon):

```bash
/opt/homebrew/bin/go build -o portik .
```

Or, if your `go` is already the right toolchain:

```bash
go build -o portik .
```

Run tests

Run the unit tests:

```bash
go test ./...
```

Feature tests

1) who — who owns a port

Start a listener (HTTP) on port 54321:

```bash
nohup python3 -m http.server 54321 > /tmp/portik_test.log 2>&1 & echo $!
# -> prints PID, e.g. 70028
```

Inspect the port:

```bash
./portik who 54321
```

Expected (example) output:

```
Port 54321/tcp
LISTEN  *:54321                  pid=70028  user=you  Python  /path/to/python -m http.server 54321
```

Stop the test server:

```bash
kill <PID>
```

2) explain — explain why a port might be stuck

Use a port that shows TIME_WAIT or other states (example uses 54321):

```bash
./portik explain 54321
```

Expected: A multi-line explanation describing listeners, possible diagnostics, docker mapping hints, and recommended actions.

3) who --docker / Docker mapping

If you have Docker, start a container that maps an internal container port to a host port:

```bash
docker run -d --name portik-nginx -p 18080:80 nginx:alpine
```

Then inspect with docker enabled:

```bash
./portik who 18080 --docker
```

Expected: `portik` will report the container ID/name and (if available) compose service mapping.

Cleanup:

```bash
docker rm -f portik-nginx
```

4) kill — terminate owner safely

Start a long-running process bound to a port:

```bash
nohup python3 -m http.server 15432 > /tmp/portik_kill.log 2>&1 & echo $!
# note PID
```

Verify:

```bash
./portik who 15432
```

Kill (safe by default; `--force` to skip prompts):

```bash
./portik kill 15432
```

Expected: `portik` prints the action it will take and (if allowed) stops the owner process.

5) restart — stop and rerun last command

`restart` attempts to rerun the last command for the owning process (it uses recorded history). To test a simple restart flow:

- Manually start a process using a shell script that records its command in history (or use the CLI to record history). The exact `restart` behavior depends on recorded history entries.
- Example (manual flow): kill the process, then run the last command that launched it again.

Use:

```bash
./portik restart 15432
```

Expected: `portik` attempts a safe restart and prints the new pid / status.

6) watch — monitor port ownership over time

```bash
./portik watch 54321 --interval 5s
```

Expected: Periodic reports showing changes to the port owner. Use this while you start/stop processes to see transitions.

7) JSON output

Many commands support `--json` to emit machine-readable output:

```bash
./portik who 54321 --json
```

Use the JSON output to integrate with scripts or tests.

8) History commands

Record and inspect port ownership history (if available):

```bash
./portik history 54321
```

9) Troubleshooting on macOS (LC_UUID / toolchain notes)

- If you see `dyld: missing LC_UUID load command`, build with a modern Go toolchain for Apple Silicon (or the matching arch). Example using Homebrew Go:

```bash
/opt/homebrew/bin/go build -o portik .
```

Or update PATH to prefer `/opt/homebrew/bin`.

10) Automated smoke test (example script)

Save the following as `scripts/smoke-test.sh` and run it to perform a quick end-to-end exercise (requires `python3`):

```bash
#!/usr/bin/env bash
set -euo pipefail

BUILD_CMD="/opt/homebrew/bin/go"
if command -v go >/dev/null && [[ $(go version | sed -E 's/.* darwin\/(.*)$/\1/') == "arm64" ]]; then
  BUILD_CMD=go
fi

echo "Building..."
$BUILD_CMD build -o portik .

echo "Start test server on 54321"
nohup python3 -m http.server 54321 > /tmp/portik_test.log 2>&1 &
PID=$!
sleep 1

echo "Running who"
./portik who 54321

echo "Running explain"
./portik explain 54321

echo "Cleaning up"
kill $PID || true

echo "Smoke test done"
```

Run it:

```bash
bash scripts/smoke-test.sh
```

Notes and expectations
- Some features (Docker mapping, restart) depend on environment and available metadata.
- `kill` and `restart` may require elevated privileges for some PIDs; use `sudo` if necessary.
- Tests that depend on `docker` require the Docker daemon running and accessible.

If you'd like, I can:
- Add the smoke test script to the repo and make it executable, or
- Run the smoke test here and paste the output.
