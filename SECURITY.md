# Security policy

WSN grants network reachability and should be treated like a VPN gateway.

- Report vulnerabilities privately to the repository owner rather than opening a public issue with credentials or network details.
- Never commit `wsn-state`, generated bundles, `.env`, server state, private keys, client keys, real corporate routes, or internal hostnames.
- Revoke a client immediately if its bundle or key is exposed, regenerate `server.json`, and redeploy the relay.
- Rotate the deployment CA if `relay-ca.key` is exposed. This requires issuing a new CA and reinstalling every client.
- Rotate only the relay leaf certificate when `relay.key` is exposed; clients can keep the same CA.
- Verify release checksums and GitHub artifact attestations before creating private client bundles.
