# portik

[![ci](../../actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)

<p align="center">
  <img src="./assets/portik-logo.svg" alt="portik logo" width="640" />
</p>

A developer-friendly CLI to inspect, explain, and manage port ownership. Find out who's using a port, why it's stuck, and how to safely recover it.

## Quick Start

```bash
portik who 5432        # Who owns the port?
portik explain 5432    # Why is it stuck?
portik kill 5432       # Safely terminate the owner
portik restart 5432    # Stop and restart the last command
```

## Key Features

- **Inspect**: Show all listeners on a port (PID, user, process, command)
- **Diagnose**: Explain why a port is stuck (TIME_WAIT, zombies, permissions, IPv4/IPv6 confusion)
- **Manage**: Kill, restart, or reserve ports safely
- **Monitor**: Watch ownership changes, view history, trace process trees
- **Docker**: Show container-to-port mappings
- **Lint**: Flag security issues (ports exposed to 0.0.0.0, privileged ports, etc.)

## Installation

### Using `go install` (Recommended)

Requires Go 1.24+:

```bash
# Standard installation
go install github.com/pratik-anurag/portik@latest

# With TUI support
go install -tags tui github.com/pratik-anurag/portik@latest
```

### Build from Source

```bash
# Build locally
go build .
./portik --help

# Install globally
go install .
```

### Homebrew / Binaries

Coming soon.

## Requirements

- **Go 1.24+** (for building)
- **Linux**: `ss` and `ps` in PATH
- **macOS**: `lsof` and `ps` in PATH (elevated privileges recommended)
- **Optional**: `docker` CLI for `--docker` features

## Common Commands

### Inspect Port Ownership

```bash
portik who 5432                          # Who owns the port?
portik who 5432 --docker                 # Include Docker mapping
portik who 5432 --follow --interval 2s   # Watch for changes
```

### Diagnose Problems

```bash
portik explain 5432      # Why is it stuck?
portik explain 5432 --docker
portik lint              # Find security issues across all listeners
```

### Manage Ports

```bash
portik kill 5432         # Gracefully terminate, then force kill
portik restart 5432      # Smart restart (captures and replays command)
portik wait 8080 --listening --timeout 60s   # Wait for service to start
```

### Monitor & History

```bash
portik watch 5432 --interval 10s         # Record ownership changes
portik history 5432 --since 7d           # View recent history
portik history 5432 --detect-patterns    # Detect patterns
portik daemon --ports 5432,6379 --interval 30s --docker
```

### Find Free Ports

```bash
portik free                               # Get an ephemeral free port
portik free --ports 3000-3999            # Find free port in range
portik reserve 5432 --for 2m             # Reserve port for duration
portik use --ports 3000-3999 -- npm run dev   # Run command on free port
```

### Scan Ports

```bash
portik scan --ports 3000-3010            # Scan range
portik scan --ports 22,80,443,5432       # Scan list
portik scan --all                         # Scan ALL listening ports on system
portik scan --all --owner postgres       # Filter by owner
portik scan --all --min-port 3000 --max-port 9999  # Filter by port range
portik top --ports 3000-3010 --top 5     # Top ports by connection count
```

### Trace & Debug

```bash
portik blame 5432        # Process tree (who started this?)
portik trace 5432        # Trace ownership/proxy layers
portik conn 5432 --top 10   # Top clients to a port
portik graph --top 20    # Local dependency graph between processes
```

### Graph (Local Dependencies)

```bash
portik graph                         # Default text output
portik graph --ports 5432,6379       # Limit to specific ports
portik graph --top 25                # Show top edges
portik graph --dot                   # Graphviz DOT output
portik graph --json                  # JSON output
```

## Command Reference

| Command | Description |
|---------|-------------|
| `who` | Show listeners on a port |
| `explain` | Diagnose why a port is stuck |
| `kill` | Gracefully terminate port owner |
| `restart` | Smart restart (stop + replay command) |
| `watch` | Poll and record ownership changes |
| `daemon` | Monitor multiple ports continuously |
| `history` | View ownership history in time window |
| `blame` | Show process tree and "who started this" |
| `trace` | Trace ownership/proxy layers |
| `top` | Top ports by connection count |
| `scan` | Scan ports (range/list or discover all with `--all`) |
| `free` | Find a free port |
| `reserve` | Reserve a port temporarily |
| `use` | Run command on a free port |
| `conn` | Show connections to a port |
| `graph` | Local dependency graph between processes |
| `wait` | Wait for port to become listening/free |
| `lint` | Lint current listeners for issues |
| `tui` | Interactive port management (optional) |

## TUI (Interactive Dashboard)

Optional interactive interface (like `htop` for ports):

```bash
# Run directly
go run -tags tui . tui --ports 5432,6379 --interval 2s

# Or build binary with TUI enabled
go build -tags tui -o portik .
./portik tui --ports 5432,6379 --interval 2s --docker
```

### TUI Keybindings

- **↑/↓** or **j/k** — Move selection
- **Tab** — Toggle Who/Explain views
- **w** — Who view
- **e** — Explain view
- **r** — Refresh now
- **/** — Filter/search
- **Esc** — Clear filter/cancel
- **?** / **h** — Toggle help
- **q** — Quit
- **K** — Kill (with `--actions`)
- **R** — Restart (with `--actions`)

## Platform Support

- **Linux** — uses `ss` and `ps`
- **macOS** — uses `lsof` and `ps` (elevated privileges recommended)
- **Windows** — not fully supported yet

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "Address already in use" after restart | Run `portik explain <port>` for TIME_WAIT sockets; retry after delay |
| No PID shown | Re-run with `sudo` and ensure `lsof`/`ss` is available |
| Port unreachable from remote machine | Check for loopback-only listeners; bind to `0.0.0.0` or `[::]` |
| Container port confusion | Use `portik who <port> --docker` to see host-to-container mappings |
| Port listening but unreachable | Check local firewall and allow the port |
| Missing PID/cmdline | Elevated privileges (sudo) required on macOS and some Linux systems |

## Common Issues

**Why does portik need `sudo`?**  
Socket-to-PID resolution is restricted without elevated privileges on macOS and some Linux systems.

**Can portik manage container ports?**  
Yes, use `--docker` flag. It shows host-to-container mappings and container names.

**What if I need to track history?**  
History is stored at `~/.portik/history.json`. Use `portik history` to view it. History is safely managed:
- Up to 200 entries per port (oldest discarded when limit reached)
- Safe concurrent writes if multiple portik daemons/watches are running
- Deduplicates consecutive identical states to reduce file growth

**Can I run multiple portik daemons simultaneously?**  
Yes, they're safe to run concurrently. History writes are serialized with a mutex to prevent corruption.

**Is it safe to use kill/restart?**  
Yes. Both commands are conservative by default:
- Require confirmation (unless `--yes`)
- Refuse to act on processes not owned by your user (unless `--force`)

## Permissions & Safety

Destructive actions (kill, restart, TUI actions) are conservative by default:

- ✓ Confirmation prompts (unless `--yes`)
- ✓ Refuse to act on processes not owned by you (unless `--force`)
- ✓ Use `sudo` when needed for full PID/cmdline visibility

## Design & Limitations

**Design:**
- Port inspection is OS-specific (Linux: `ss`, macOS: `lsof`; results normalized)
- Process metadata enriched via `ps` parsing
- Diagnostics are heuristic to guide debugging, not replace system analysis
- History writes are serialized with a mutex to ensure concurrent safety across multiple processes

**History Management:**
- Per-port limit: 200 entries (oldest discarded when exceeded)
- Consecutive identical states are deduplicated to reduce file growth
- Multiple daemons/watches can run concurrently without corruption
- Lock timeout: 7 seconds (falls back gracefully if timeout exceeded)
- File location: `~/.portik/history.json`

**Limitations:**
- Socket → PID resolution requires elevated privileges in some cases
- Docker mapping relies on local `docker` CLI; not exhaustive for all runtimes
- `restart` relies on recorded command history; may not reproduce complex environments
- History stored in single JSON file; very large histories may be slow to query
- Global per-port limit (200 entries) may be insufficient for long-running monitoring

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Please keep behavior conservative and maintain backward compatibility for JSON output.

## License

MIT — See [LICENSE](./LICENSE).

## Project Status

**Alpha**. Active development. Interfaces and JSON output may change. The focus is on correctness over exhaustive platform coverage.
