# portik



<p align="center">
  <img src="./assets/portik-logo.svg" alt="portik logo" width="640" />
</p>

## Table of Contents

- [Overview](#overview)
- [1-minute quickstart](##1-minute-quickstart
- [Real problems solved](#real-problems-solved)
- [Install](#install)
- [Quickstart (more examples)](#quickstart-more-examples)
  - [Scan / Free / Reserve](##scan--free--reserve)
  - [commands
  - [TUI (optional)](##tui-optional)
- [Troubleshooting in the wild](#troubleshooting-in-the-wild)
- [Platform support](#platform-support)
- [Contributing](#contributing)
- [License](#license)

## Overview


portik is a developer-friendly CLI to inspect, explain, and manage port ownership.

It helps answer:

- Who is using a port (e.g., 5432)
- Why a port is stuck or bind fails (TIME_WAIT, zombie processes, permission issues, IPv4/IPv6 bind confusion)
- Whether a port is mapped from a container and which container/service
- Whether it's safe to restart the owner (kill + restart last command)
- Who started a process (process tree and system hints)

Note: resolving sockets → PIDs can require elevated privileges on some systems (especially macOS). If you see missing PID/cmdline, try `sudo`.

---

## 1-minute quickstart

```bash
# who owns the port?
portik who 5432

# why is it stuck?
portik explain 5432

# follow changes (delta-only)
portik who 5432 --follow --interval 2s
```


## Real problems solved

- Restarted a service and hit “address already in use”? `portik explain` will show TIME_WAIT sockets, zombie listeners, or other hardware hints.
- App listens only on `127.0.0.1` and refuses remote traffic? The loopback/literal binding warning explains why and how to fix it.
- Docker port conflict? `portik who --docker` shows the container name/ID and the service that owns the port.

## Project status

portik is in active development and is currently **alpha**. Interfaces and output may change, especially JSON fields. The focus is on correct results over exhaustive platform coverage.

## Install

### Build from source

```bash
git clone https://github.com/pratik-anurag/portik
cd portik
go build ./cmd/portik
./portik --help
```

## Requirements

- Go 1.22+ (use an up-to-date toolchain on macOS Apple Silicon)
- Linux: `ss` and `ps` in `PATH`
- macOS: `lsof` and `ps` in `PATH`
- Optional: `docker` in `PATH` for `--docker` features

## Quickstart (more examples)

```bash
# who owns the port?
portik who 5432

# explain why it may be stuck
portik explain 5432

# include Docker port mapping (optional)
portik who 5432 --docker
portik explain 5432 --docker

# terminate owner (safe by default)
portik kill 5432

# smart restart: stop + rerun last command (safe by default)
portik restart 5432

# record & watch ownership changes
portik watch 5432 --interval 10s
portik history 5432 --since 7d
portik history 5432 --since 30d --detect-patterns

# follow changes (delta-only)
portik who 5432 --follow --interval 2s

# trace ownership/proxy layers
portik trace 5432

# daemon (foreground; use nohup/systemd if desired)
portik daemon --ports 5432,6379 --interval 30s --docker

# blame / process tree ("who started this?")
portik blame 5432 --docker
```

## Scan / Free / Reserve

### Scan ports (range/table)

Scan a list or range of ports and print a quick table of what’s in use.

```bash
# scan a range
portik scan --ports 3000-3010

# scan a mixed spec
portik scan --ports 22,80,443,5432,6379,8080

# scan with Docker mapping
portik scan --ports 3000-3010 --docker

# UDP scan
portik scan --ports 53,123 --proto udp

# JSON output (for scripts)
portik scan --ports 3000-3010 --json

# tune concurrency (default: CPU count, max 32)
portik scan --ports 3000-3999 --concurrency 16

# ask OS for an ephemeral free port (default)
portik free
# -> 51243

# find a free port within a range
portik free --ports 30000-40000

# UDP free port
portik free --proto udp

# JSON output
portik free --ports 30000-40000 --json

portik reserve --for 30s

# reserve a specific port for 2 minutes
portik reserve 5432 --for 2m

# reserve UDP port
portik reserve --proto udp --for 45s

# reserve on a specific bind address
portik reserve --bind 0.0.0.0 --for 30s

# JSON output
portik reserve --for 30s --json

## `use` — run a command on a free port automatically

`portik use` picks a free port (optionally from a range) and runs your command with:

- `PORT=<chosen>` set in the environment
- optional `{PORT}` template replacement in args (no shell)
- optional `--shell` mode to allow `$PORT` expansion

### Basic usage

# pick an ephemeral free port and run a command
portik use -- python -m http.server

# pick a free port from the range 3000-3999
portik use --ports 3000-3999 -- npm run dev

#If your command accepts a port argument, you can replace {PORT} in args:
portik use --ports 3000-3999 --template -- python -m http.server {PORT}

#Use this if your command string relies on $PORT expansion (or shell operators):
portik use --ports 3000-3999 --shell -- sh -lc 'echo "PORT=$PORT"; python -m http.server $PORT'

#UDP mode
portik use --proto udp --ports 40000-40100 --print

# top clients to Postgres
portik conn 5432 --top 10

# only ESTABLISHED
portik conn 5432 --state ESTABLISHED

# top ports by connection count
portik top --ports 3000-3010 --top 5

# wait until service starts
portik wait 8080 --listening --timeout 60s

# wait until port is free
portik wait 8080 --free --timeout 30s
```

History is stored at: `~/.portik/history.json`

## Commands

- `portik who <port>` — show listeners for a port.
	- Flags: `--proto tcp|udp` (default `tcp`), `--docker`, `--json`, `--follow`, `--interval`

- `portik explain <port>` — adds diagnostics: port in use, IPv6-only hint, TIME_WAIT sockets, zombie hints, privileged port hints, docker mapping hints.

- `portik kill <port>` — graceful terminate then force kill after timeout.
	- Flags: `--timeout`, `--force`, `--yes`, `--proto`, `--docker`

- `portik restart <port>` — smart restart (captures cmdline, terminates owner, restarts detached).
	- Flags: `--timeout`, `--force`, `--yes`, `--docker`, `--container`, `--proto`

- `portik watch <port>` — poll periodically and record ownership changes to history.
	- Flags: `--interval`, `--proto`, `--docker`, `--json`

- `portik daemon` — monitor multiple ports and record history (foreground).
	- Flags: `--ports` (required), `--interval`, `--proto`, `--docker`, `--quiet`, `--json`

- `portik history <port>` — view history in a time window.
	- Flags: `--since`, `--detect-patterns`, `--json`

- `portik blame <port>` — process tree and "who started this" hints.
	- Flags: `--depth`, `--proto`, `--docker`, `--json`

- `portik top` — top ports by connection count (scan list/range).
	- Flags: `--ports`, `--top`, `--clients`, `--proto`, `--json`

- `portik trace <port>` — trace ownership/proxy hints for a port.
	- Flags: `--proto`, `--docker`, `--json`

## TUI (optional)

portik includes an optional interactive TUI (like `htop`, but for ports). It's not included in the default build to keep the CLI lightweight.

Build / Run (with TUI):

```bash
# run directly
go run -tags tui ./cmd/portik tui --ports 5432,6379 --interval 2s --docker

# or build a binary with TUI enabled
go build -tags tui -o portik ./cmd/portik
./portik tui --ports 5432,6379 --interval 2s --docker
```

TUI flags: `--ports`, `--interval`, `--proto`, `--docker`, `--actions`, `--force`

Keybindings (TUI):

- ↑/↓ or j/k — move selection
- Tab — toggle Who / Explain
- w — Who view
- e — Explain view
- r — refresh now
- / — filter/search
- Esc — clear filter / cancel
- ? or h — toggle help
- q — quit

Actions (only if started with `--actions`):

- K — kill selected port owner (confirm)
- R — restart selected port owner (confirm)

Each port shows a sparkline representing ownership-change activity over the last 24 hours.

## Examples

Who (text):

```
Port 5432/tcp
LISTEN 127.0.0.1:5432  pid=8123  user=me  postgres  /usr/lib/postgresql/...
```

Explain (high-level):

```
Summary
- [INFO] Port is in use
- [WARN] Only IPv6 listener detected (IPv4 bind confusion)
- [INFO] TIME_WAIT sockets present
```

## Troubleshooting in the wild

- "Address already in use" after a restart: check `portik explain <port>` for TIME_WAIT and retry after a short delay.
- Port looks busy but no PID is shown: re-run with sudo/admin and ensure `lsof`/`ss` is available.
- Works on localhost but not from another machine: look for loopback-only listeners and bind to `0.0.0.0` or `[::]`.
- Container port confusion: use `portik who <port> --docker` to see host-to-container mappings.
- Port is listening but still unreachable: check if a local firewall is active and allow the port.

## Platform support

- Linux: uses `ss` and `ps`
- macOS: uses `lsof` and `ps`
- Windows: not supported yet (builds, but core inspection/kill/restart are incomplete)

## Limitations

- Socket → PID resolution can be restricted without elevated privileges.
- Docker mapping relies on the local `docker` CLI and is not exhaustive for every runtime.
- `restart` relies on recorded command history and may not reproduce complex launch environments.
- History is stored in a single JSON file; large histories can be slow to query.

## Design notes

- Port inspection is OS-specific: Linux uses `ss`, macOS uses `lsof`; results are normalized into a common model.
- Process metadata is enriched via `ps` parsing, so fields like cmdline can be empty.
- Diagnostics are heuristic and intended to guide debugging, not replace system-level analysis.

## Safety notes

Destructive actions (kill, restart, TUI actions) are conservative by default:

- confirmation prompts (unless `--yes`)
- refuses to act on processes not owned by your user (unless `--force`)

Use `sudo` when needed for PID/cmdline visibility.

## Contributing

See CONTRIBUTING.md. Please keep behavior conservative and backwards compatible for JSON output.

## License

MIT (see LICENSE).
