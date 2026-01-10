# portik

**portik** is a developer-friendly CLI to inspect, explain, and manage port ownership.

It answers:

- **Who is using port 5432?**
- **Why can’t my app bind to this port?** (TIME_WAIT, zombie process, permissions, IPv4/IPv6 confusion)
- **Is this port owned by a Docker container? Which service?**
- **Can I safely restart the process that owns this port?**
- **Who keeps taking this port every morning?** (port ownership history)

> Note on permissions: mapping network sockets to PIDs can require elevated privileges on some OSes (notably macOS).  
> Run with `sudo` if you see missing PIDs/process info.

---

## Install

### Homebrew (recommended)
WIP.

### Download a binary
WIP (GitHub Releases).

### Build from source

```bash
git clone https://github.com/pratik-anurag/portik
cd portik
go build ./cmd/portik
./portik --help
