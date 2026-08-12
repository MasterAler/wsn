# WSN v2

WSN carries a private Ethernet segment through authenticated WebSockets. It is intended for environments where an administrator has approved outbound HTTPS/WebSocket access but a conventional VPN transport is unavailable.

WSN is not a replacement for workplace authorization. Deploy it only for networks and systems you are permitted to access.

## Architecture

```mermaid
flowchart LR
    W[Windows client\nTAP + WSN service] -->|WSS :443| V[VDS\nCaddy + relay]
    U[Ubuntu client\nTAP + systemd] -->|WSS :443| V
    G[Workplace gateway\nTAP + systemd] -->|WSS :443| V
    G -->|IPv4 forwarding + NAT| C[Approved corporate CIDRs]
```

The VDS is only an Ethernet relay and never joins the overlay. Each endpoint has a fixed client identity, random key, virtual MAC, and overlay address. Peers share the Layer-2 segment. The workplace gateway forwards only the configured corporate CIDRs, on all ports and protocols, and masquerades traffic so internal hosts can return it normally.

The gateway does not install WSN-specific `INPUT` firewall rules. Services already bound on its overlay address therefore remain governed by the host's existing firewall.

## Security model

- TLS 1.3 uses a deployment-specific private CA. Clients load that CA only inside WSN; installers do not add it to an operating-system trust store.
- Authentication uses a fresh random challenge and per-client HMAC-SHA256 key. A key can be revoked without rotating every client.
- The relay binds each identity to a configured virtual MAC and rejects source-MAC spoofing.
- Client and relay queues are bounded; oversized frames and slow peers are disconnected.
- The root CA key and provisioning state stay on the administrator's machine and must be backed up encrypted. Only a leaf TLS key and the relay's client-key database go to the VDS.
- A generated client bundle contains that client's key. Transfer it privately, install it once, and delete the transfer copy.

Never reuse the historical v1 shared secret. If a credential has appeared in chat, shell history, a command line, or a world-readable unit file, rotate it.

## Build

Go 1.22.2 or newer is required.

Linux clients require systemd, `iproute2`, and `/dev/net/tun`; gateway installations additionally require `iptables`. Windows installation requires elevated PowerShell and an official TAP-Windows driver. The VDS requires Docker Engine with the Compose plugin.

```sh
go test -race ./...
CGO_ENABLED=0 go build -o dist/wsn-server ./cmd/wsn-server
CGO_ENABLED=0 go build -o dist/wsn-client-linux-amd64 ./cmd/wsn-client
CGO_ENABLED=0 go build -o dist/wsnctl ./cmd/wsnctl
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o dist/wsn-client-windows-amd64.exe ./cmd/wsn-client
```

Tagged GitHub releases build and attest Linux/Windows clients and `wsnctl`. They also publish `ghcr.io/masteraler/wsn:<tag>`. Production deployment must use a version tag or image digest, never `latest`.

Verify downloaded release artifacts before bundling them:

```sh
sha256sum -c SHA256SUMS
gh attestation verify ./wsn-client-linux-amd64 --repo MasterAler/wsn
```

## Provision a deployment

All commands below run on a trusted administrator machine. State defaults to `./wsn-state`, which is ignored by Git.

### 1. Select networks

Inspect the route table of every client and the gateway before selecting the overlay and corporate routes:

```sh
ip -br -4 address
ip -4 route show table main
```

The overlay must not overlap home LANs, Docker/VM networks, another VPN, or corporate destinations. Corporate routes should be the narrowest currently valid CIDRs.

Do not copy the old `172.16.0.0/12` route to the described Astra gateway: it overlaps `docker0` at `172.17.0.0/16`. The gateway installer deliberately rejects that configuration. Obtain the current narrower corporate CIDRs or readdress Docker first.

### 2. Initialize credentials and TLS

The following documentation addresses are examples only:

```sh
dist/wsnctl init \
  -state ./wsn-state \
  -public-ip 203.0.113.10 \
  -overlay 100.96.42.0/24 \
  -gateway 100.96.42.1
```

This creates a ten-year root CA, a two-year relay leaf certificate containing the public IP SAN, and an initially empty relay configuration. Back up `wsn-state` encrypted and offline.

### 3. Add the workplace gateway

Routes are comma-separated canonical CIDRs. Replace these examples with authorized, collision-free current values:

```sh
dist/wsnctl add-client \
  -state ./wsn-state \
  -id workplace-gateway \
  -os linux \
  -role gateway \
  -address 100.96.42.1 \
  -device wsn0 \
  -egress eth0 \
  -routes 10.0.0.0/16,10.5.0.0/16,172.19.102.0/24
```

The gateway's corporate routes are used for forwarding validation and firewall/NAT rules. They are not installed via the overlay.

### 4. Add any number of clients

```sh
dist/wsnctl add-client \
  -state ./wsn-state \
  -id alice-windows \
  -os windows \
  -address 100.96.42.2 \
  -routes 10.0.0.0/16,10.5.0.0/16,172.19.102.0/24

dist/wsnctl add-client \
  -state ./wsn-state \
  -id bob-ubuntu \
  -os linux \
  -address 100.96.42.3 \
  -routes 10.0.0.0/16,10.5.0.0/16,172.19.102.0/24
```

Addresses and MACs must be unique, but there is no two-user limit:

```sh
dist/wsnctl list-clients -state ./wsn-state
```

## Deploy the VDS

Install Docker Engine and the Compose plugin from Docker's official Ubuntu instructions. Configure the host/provider firewall to expose the chosen SSH port and `443/tcp` only.

Create a server-only archive. It intentionally excludes the root CA key and full provisioning state:

```sh
dist/wsnctl server-bundle -state ./wsn-state -output wsn-server-private.tar.gz
```

On the VDS:

```sh
git clone https://github.com/MasterAler/wsn.git /opt/wsn
cd /opt/wsn/deploy/server
cp .env.example .env
# Set the real static IP and immutable relay image tag/digest in .env.
mkdir /root/wsn-server-private
tar -xzf /path/to/wsn-server-private.tar.gz -C /root/wsn-server-private
sudo ./install.sh /root/wsn-server-private
```

Compose publishes only Caddy on `443/tcp`. The relay has no host port and accepts trusted proxy metadata only from the private Compose network. Logs rotate at 10 MiB with three files, and each service is limited to 128 MiB.

After adding or revoking a client, create and deploy a fresh server bundle, then run `install.sh` again. Connections briefly restart.

Renew the leaf certificate before its two-year expiry without changing clients:

```sh
dist/wsnctl rotate-certificate -state ./wsn-state
dist/wsnctl server-bundle -state ./wsn-state -output wsn-server-private.tar.gz
```

Check expiry from a monthly timer or monitoring job on the VDS:

```sh
/opt/wsn/deploy/server/check-certificate.sh
```

It exits nonzero when fewer than 30 days remain.

## Create and install client bundles

### Ubuntu 22.04/24.04 and Astra gateway

```sh
dist/wsnctl bundle \
  -state ./wsn-state \
  -id bob-ubuntu \
  -client-binary ./dist/wsn-client-linux-amd64 \
  -output bob-ubuntu-linux.tar.gz
```

For Astra, build the same static binary locally if desired:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o wsn-client ./cmd/wsn-client
```

Generate the gateway bundle with `-id workplace-gateway`. Transfer, extract, and install either Linux bundle:

```sh
tar -xzf CLIENT-linux.tar.gz
cd CLIENT-linux
sudo ./install-linux.sh
systemctl status wsn-net wsn-client
# The gateway additionally has wsn-gateway.service.
```

The installer:

- creates a locked `wsn` system user;
- validates existing kernel routes before changing networking;
- creates the TAP and persistent routes through a oneshot unit;
- runs the client unprivileged with systemd hardening;
- enables forwarding and dedicated `WSN_FORWARD`/`WSN_POSTROUTING` chains only for gateway bundles.

The gateway script does not modify `INPUT`. Its forwarding chain allows every port/protocol inside configured corporate CIDRs, rejects other WSN forwarding, and removes only its own rules on uninstall.

### Windows 10/11 x64

Obtain the official signed TAP-Windows installer and matching `tapctl.exe` from OpenVPN. Keep their original signatures. `wsnctl` records their SHA-256 hashes in the private bundle, and the installer additionally requires a valid OpenVPN Authenticode signer.

```sh
dist/wsnctl bundle \
  -state ./wsn-state \
  -id alice-windows \
  -client-binary ./dist/wsn-client-windows-amd64.exe \
  -tap-installer /secure/path/tap-windows-installer.exe \
  -tapctl /secure/path/tapctl.exe \
  -output alice-windows.zip
```

Transfer the ZIP privately. Extract it, open an elevated PowerShell in that directory, and run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install-windows.ps1
Get-Service WSNClient
```

The installer rejects overlapping routes, installs the signed driver, creates the fixed-MAC TAP adapter, adds persistent routes, protects configuration for SYSTEM and Administrators, and configures service recovery. `uninstall-windows.ps1` removes WSN while retaining the shared TAP driver.

### Manual upgrades and rollback

Verify the new generic client artifact and its GitHub attestation first. Then use the upgrade helper from the original private bundle; configuration and identity are preserved:

```sh
sudo ./upgrade-linux.sh ./wsn-client-linux-amd64 EXPECTED_SHA256
sudo ./rollback-linux.sh
```

```powershell
.\upgrade-windows.ps1 -Binary .\wsn-client-windows-amd64.exe -Sha256 EXPECTED_SHA256
.\rollback-windows.ps1
```

Each upgrade retains one previous binary and automatically restores it if the service cannot restart.

## Operations

Revoke a lost or retired client and redeploy the server bundle:

```sh
dist/wsnctl revoke-client -state ./wsn-state -id alice-windows
dist/wsnctl server-bundle -state ./wsn-state -output wsn-server-private.tar.gz
```

For Linux diagnostics:

```sh
systemctl status wsn-net wsn-client wsn-gateway
journalctl -u wsn-client -u wsn-gateway --since today
ip address show wsn0
ip route
sudo iptables -S WSN_FORWARD
sudo iptables -t nat -S WSN_POSTROUTING
```

For VDS diagnostics:

```sh
cd /opt/wsn/deploy/server
docker compose ps
docker compose logs --tail=200 relay caddy
curl --cacert /secure/path/relay-ca.crt https://PUBLIC_IP/
```

A `404` from `/` confirms Caddy is reachable without exposing a public health endpoint. Client logs should show an authenticated session after installation.

## Scope exclusions

WSN does not manage corporate DNS or host entries, corporate certificate authorities, CIFS mounts, workplace user accounts, or SSH keys. In particular, do not restore SMB1 mount commands or inline share passwords as part of this deployment.
