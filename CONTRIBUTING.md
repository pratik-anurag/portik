# Contributing

Thanks for contributing to **portik**.

## Requirements
- Go 1.24+
- On Linux: `ss` and `ps` in PATH
- On macOS: `lsof` and `ps` in PATH
- Optional: `docker` in PATH for `--docker` features

## Local dev
```bash
go test ./...
go run . --help
```

## How to report bugs

Please open a GitHub issue with:
- Your OS and architecture
- The exact command you ran
- The full output (or a minimal repro if it's large)
- Whether you ran with elevated privileges (sudo/admin)
- Any relevant environment details (container/WSL, Docker, etc.)
