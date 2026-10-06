<p align="center"><img src="docs/logo.svg" alt="Passbolt" height="40"></p>

# Passbolt Menu Bar

A small native macOS menu-bar app (SwiftUI, macOS 14+, Apple Silicon + Intel) to search your
existing Passbolt (v5, RSA key) vault and copy credentials. No telemetry, no third-party servers.

> Status: written against the Passbolt OpenAPI spec in `open-api-specs.yaml`. It has been unit
> tested with mock servers and a real OpenPGP round-trip, but **not yet run against a live Passbolt
> server** and not independently audited. See [SECURITY.md](SECURITY.md).

## Build

Requirements: Xcode 15+, Go (`brew install go`), XcodeGen (`brew install xcodegen`).

```sh
./scripts/build-pgp.sh        # builds Pgpbridge.xcframework from ./PGPBridge (Go + GopenPGP) - local, from source
xcodegen generate             # creates PassboltMenuBar.xcodeproj from project.yml
xcodebuild -project PassboltMenuBar.xcodeproj -scheme PassboltMenuBar \
  -configuration Release -derivedDataPath build -destination 'generic/platform=macOS' build
open build/Build/Products/Release/PassboltMenuBar.app
swift test                    # unit tests for the core library
```

The app is ad-hoc signed. Set your own team in Xcode for a stable signature (this also keeps Keychain
access prompts from reappearing after each rebuild).

## Configure

1. Find your **user ID** (UUID): in the Passbolt web UI open *Users*, select yourself; the URL ends in
   `/app/users/view/<uuid>`.
2. Have your **private key file** (`.asc`, from your Passbolt recovery kit) and its passphrase.
3. Click the menu-bar icon → enter the https server URL, user ID, choose the key file, enter the
   passphrase → Connect. Nothing is stored unless login succeeds.

## How authentication works

Passbolt's documented GpgJwtAuth flow: fetch the server public key (`GET /auth/verify.json`), sign a
challenge with your key and encrypt it to the server (`POST /auth/jwt/login.json`), decrypt and
verify the server's signed reply, and use the returned JWT as a Bearer token. The server key
fingerprint is pinned on first login; a different key later is rejected. Tokens live in memory only.
On token expiry the app re-runs login instead of persisting a refresh token.

Resource metadata (name, username, URL) is decrypted locally after unlock (v5 shared/personal
metadata keys, plus plaintext v4 metadata). Secrets are fetched and decrypted only when you open a
resource. All OpenPGP work is done by GopenPGP (ProtonMail, MIT) via a ~100-line wrapper in
`PGPBridge/`. The app implements no cryptography itself (TOTP uses CryptoKit HMAC).

## Where secrets are stored

| Item | Location |
|---|---|
| Private key, passphrase | macOS Keychain (`WhenUnlockedThisDeviceOnly`) |
| Server URL, user ID, server/key fingerprints, timeouts | UserDefaults (not secret) |
| Tokens, decrypted metadata/secrets | Memory only; wiped on lock |

Unlocking requires Touch ID / Apple Watch / Mac password (an app-level gate; see SECURITY.md for the
limits of this). The passphrase is stored so unlock can be biometric.

## What leaves the computer / what is cached

- Only HTTPS requests to your Passbolt server, listed in `PassboltClient.swift`. Nothing else: no
  analytics, no proxy, no update checks.
- Nothing decrypted is written to disk and no encrypted vault cache is kept (the list is re-fetched at
  each unlock).
- Copied values go to the system clipboard (flagged concealed) and are cleared after the timeout
  (default 30 s) only if the clipboard still holds that same value.

## Clear local credentials

Settings → Security → *Clear Keychain credentials*, or manually delete the Keychain items with
service `local.passbolt-menubar`, and `defaults delete local.passbolt.menubar`.

## Usage

Menu-bar icon (or global shortcut, default ⌃⌥Space, configurable) → type to search → ↑/↓ + Return to
open → copy buttons. ⌘C copies the password, ⇧⌘C the username, Esc goes back/closes, ⌘, settings,
⌘Q quits.

## Layout

```
App/            SwiftUI + AppKit shell (status item, popover, settings, hotkey)
Sources/PassboltKit/  API client, models, Keychain, clipboard, view-model (no UI)
PGPBridge/      Go wrapper over GopenPGP (built locally to an xcframework)
Tests/          unit tests with mock server responses and throwaway test keys
```

## Reporting vulnerabilities

See [SECURITY.md](SECURITY.md).

## Trademark

This is an unofficial, community client. It is not affiliated with or endorsed by Passbolt SA. The Passbolt
logo files in `docs/` are Passbolt's trademarks and are not covered by this project's MIT licence.
