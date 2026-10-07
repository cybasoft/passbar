# Contributing

1. Build as described in [README.md](README.md#build); `swift test` and `go test ./...` (in `PGPBridge/`) must pass.
2. Keep the app free of logging, telemetry, and non-HTTPS network access. Do not add cryptography outside `PGPBridge/`.
3. Never put real credentials, keys, or server URLs in issues, tests, or commits. Use the throwaway keys in `Tests/`.
4. Report security problems privately, as described in [SECURITY.md](SECURITY.md).
5. Do not add Passbolt logos or branding; see the Trademark section of the README.
