# Security

## Reporting a vulnerability

Please do not open a public issue. Email the maintainer privately (developer@cybasoft.com) with steps to reproduce. Do not include real credentials.

## Security review (author's self-review, not an independent audit)

This app has **not** been independently audited. Findings from the pre-completion review:

### Verified by grep / tests
- No logging calls (`print`, `NSLog`, `os_log`, `Logger`) anywhere in `App/`, `Sources/`, `PGPBridge/`.
- No `http://` use; the client and transport reject non-HTTPS; no custom TLS trust handling or
  certificate bypass; redirects to non-HTTPS are refused. Cookies and URL cache are disabled.
- No analytics/telemetry code; only endpoints listed in `PassboltClient.swift` are contacted.
- No file writes of secrets; only UserDefaults for non-secret settings; key file is read once from a
  user-selected path.
- Errors are fixed strings (`PassboltError`); raw responses are never shown.
- Clipboard clearing only clears content that still equals what we copied (unit tested).
- Real OpenPGP round trip, wrong passphrase and signature-mismatch paths tested (Go and Swift).

### Open findings / limitations
1. **Untested against a live Passbolt server.** The JWT login challenge fields, metadata-key and
   secret parsing follow the OpenAPI spec and Passbolt docs but only mock servers were used.
2. **Touch ID is an app-level gate, not a Keychain access-control.** The key and passphrase are
   ordinary Keychain items readable by this app's code identity. A same-user process that obtains
   Keychain access (e.g. you approve a prompt) can read them. Ad-hoc signing makes the app identity
   weak; sign with your own Developer ID for better binding.
3. **The passphrase is stored in the Keychain** next to the key (needed for biometric unlock); the key
   file is only as safe as that Keychain item.
4. **Memory hygiene is best effort.** Swift `String`s and Go's GC give no guarantee that the key,
   passphrase, or decrypted secrets are zeroed. Detail data is dropped when the popover closes or the
   app locks, and the Go key is explicitly cleared, but copies may linger until reuse.
5. **Clipboard**: the concealed flag is honoured only by cooperating clipboard managers; Universal
   Clipboard/Handoff behaviour is not controlled.
6. **Passphrase entry**: setup asks for the key passphrase in a secure field (required to unlock the
   key). It is held in memory until login succeeds, then stored in the Keychain.
7. **macOS 14 compatibility of the Go runtime** is unverified: the Go objects report a newer build
   version (linker warning) because gomobile does not accept a macOS deployment target.
8. **Supply chain**: Go modules are pinned by `go.sum` and built locally, but fetched from the Go
   module proxy at build time. Review `PGPBridge/go.sum` and consider vendoring.
9. **Performance** with very large vaults (all metadata decrypted at unlock) is unmeasured.
10. **Crash reports**: no secrets are intentionally placed in error text or stack arguments; crash
    report contents were not inspected.
11. **First-use trust**: the server key fingerprint is trusted on first login (TOFU); verify it
    out-of-band if that matters to you.
