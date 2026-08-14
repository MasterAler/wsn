# WSN v2

A Layer-2 VPN: a private Ethernet segment carried over authenticated WebSockets.
Clients and a workplace gateway connect outbound to a relay on a VDS over
`wss://<ip>/wsn`, and the relay switches raw Ethernet frames between them by
virtual MAC. See `README.md` for the deployment procedure and security model.

## Commands

```sh
go test -race ./...
go vet ./...
test -z "$(gofmt -l cmd internal)"

GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/wsn-client
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/wsnctl

shellcheck --severity=warning --exclude=SC1091,SC2154 \
  internal/provision/assets/*.sh deploy/server/*.sh
```

PowerShell assets are linted with `Invoke-ScriptAnalyzer -Severity Error`.
`.github/workflows/go.yml` is the source of truth for all of the above.

Platform-specific files (`*_windows.go`, `*_linux.go`) only compile under their
own `GOOS`, so `go build ./...` on one platform does not check the other. Both
matter here; the client ships for both.

## Layout

| Path | Role |
| --- | --- |
| `cmd/wsn-server` | relay daemon; reloads its client list on SIGHUP |
| `cmd/wsn-client` | client and gateway daemon |
| `cmd/wsnctl` | provisioning: `init`, `add-client`, `enroll`, `bundle`, `server-bundle`, `revoke-client`, `list-clients`, `rotate-certificate` |
| `internal/relay` | hub, peer queues, HMAC authentication |
| `internal/client` | session loop, reconnect backoff, TAP↔WebSocket pumps |
| `internal/tap` | TAP device open/read/write per platform |
| `internal/provision` | deployment state, CA, bundle generation |
| `internal/provision/assets` | installer scripts, embedded into `wsnctl` |
| `deploy/server` | compose stack, Caddyfile, install/reload scripts |

## Invariants worth knowing

**Installer assets are embedded.** `internal/provision/provision.go` has
`//go:embed assets/*`. Editing a `.ps1` or `.sh` there changes nothing until
`wsnctl` is rebuilt *and* affected bundles are regenerated and reinstalled.

**There is no `update-client`.** A client's routes, address and device name are
fixed at enrolment. Changing them means `revoke-client`, re-enrol under a new
identity, and reinstall on that machine. Get the route list right the first
time — verify every corporate destination resolves and is inside a declared
CIDR before enrolling.

**The relay never joins the overlay.** `writeRelayConfig` stores only ID, key
and MAC per client; routes, addresses and DNS never reach the VDS. The relay
cannot reach the corporate network and must not learn how.

**The relay config is bind-mounted by inode.** `compose.yaml` mounts
`state/server.json` as a single file. Anything that replaces that file rather
than rewriting it in place leaves the container reading the old inode, and the
relay will log a *successful* reload while running the previous client list.

**Client logs go to stdout.** systemd captures them; the Windows SCM discards
them entirely, so a Windows client's reconnects and errors are invisible unless
it is run in the foreground.

## Windows notes

These were each found the hard way; the affected lines carry comments.

- CIM/CDXML cmdlets (`New-NetIPAddress`, `Set-NetIPInterface`, …) raise
  non-terminating errors even under `$ErrorActionPreference = 'Stop'`. Pass
  `-ErrorAction Stop` explicitly or the installer reports success over failures.
- `New-NetRoute` cannot write to `PersistentStore` here — every parameter
  combination returns Windows error 87. Persistent routes go through
  `route.exe -p add`, and its exit code is not dependable, so each route is read
  back with `Get-NetRoute`.
- Windows PowerShell 5.1 parses `0xffffffff` as `Int32` `-1`. Use `0xffffffffL`.
- A TAP adapter created by `tapctl` registers `ComponentId` as `root\tap0901`,
  not `tap0901`; both spellings must be recognised.
- The TAP adapter reports as disconnected until an application opens it, and
  Windows silently ignores a DHCP change on a disconnected interface. The
  installer sets `Media Status = Always Connected` before addressing it.

## Style

Comments explain *why*, not what, and are reserved for decisions a reader would
otherwise have to rediscover — every one in this codebase earns its place. Match
the surrounding density rather than adding narration.

Commit messages are lowercase imperative subjects describing the effect
("fix the Windows client and installer, which never completed"), with a body
explaining the reasoning, and end with:

```
Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
```
