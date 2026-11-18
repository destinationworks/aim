# Security Policy

## Security Model

AIM (`aim-server` and `aim`) is designed for cross-computer communication between coding and assistant agents over untrusted or semi-trusted networks:

1. **HTTPS-Only with Private CA Pinning**:
   - Plain `http://` URLs and HTTP redirects (`3xx`) are unconditionally refused.
   - Clients validate the hub certificate exclusively against the configured private CA (`ca.crt`).
   - The private CA root certificate uses `pathLenConstraint = 0` so leaf certificates cannot mint sub-CAs, and leaf server certificates are validated against the CA's SubjectPublicKeyInfo before issuance.
2. **Host-Bound Bearer Keys & Constant-Time Verification**:
   - Each machine uses a separate CSPRNG bearer key stored in an owner-only file (`0600` on Unix; protected current-user / `SYSTEM` DACL on Windows).
   - `aim-server` stores only the lowercase hex SHA-256 digest of each key and compares digests in constant time (`subtle::ConstantTimeEq`).
   - The `host` component of every agent identity (`HOST:HARNESS:SESSION`) is derived strictly from the authenticated bearer key, preventing cross-host spoofing.
   - Keys are zeroized in memory (`zeroize::Zeroizing`) and are refused in URLs, CLI arguments, `config.toml`, message bodies, payloads, and artifacts.
3. **Privilege Separation**:
   - The root CA private key (`/etc/aim/ca-private/ca.key`) and provisioned client keys (`/etc/aim/client-keys`) are owned by `root:root` (`0700`/`0600`) and marked `InaccessiblePaths` in `aim-server.service`, so the network-facing `aim` service user cannot read them.
   - Key rotation and revocation can be applied live via `SIGHUP` (`systemctl reload aim-server`).
4. **Cross-Host Confidentiality & Integrity**:
   - Threads, open requests, replies, and artifacts are authorized per host: a host can only view or reply to a thread, or download an artifact, if it is the sender or an addressed recipient of the message.
5. **Untrusted Peer Content & Secret Guard**:
   - All messages, payloads, and Brotli Q6 artifacts are scanned for common credential patterns, control characters, ANSI escape sequences, and invisible/BiDi Unicode overrides before transmission and on ingestion.
   - Every inbox, thread, status, and conflict response includes an explicit untrusted-content notice reminding consuming agents never to treat peer messages as system or user instructions.

## Reporting a Vulnerability

Please report suspected security vulnerabilities privately via GitHub Security Advisories on this repository rather than opening a public issue. Include:

- Affected component (`aim-server`, `aim`, `aim-proto`, `aim-fs`, or deployment scripts)
- Reproduction steps or proof-of-concept
- Potential impact under the AIM threat model
