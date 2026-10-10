# Releasing PassBar

## Versioning
Semantic versioning, tags `vMAJOR.MINOR.PATCH`. The tag is the source of truth: `release.sh` injects
it as `MARKETING_VERSION` and uses the commit count as the build number.

- **PATCH**: bug fixes, no behaviour change. **MINOR**: new features, backward compatible.
  **MAJOR**: breaking changes (min macOS bump, storage/keychain format changes).
- Pre-releases: `v1.1.0-rc.1` style tags are not handled by the script; publish them by hand with
  `gh release create --prerelease`.

## One-time setup

1. In developer.apple.com → Certificates, create a **Developer ID Application** certificate for UA5R4WVYA6 (needs the Account Holder role) and install it in your login keychain.
2. Create an app-specific password at appleid.apple.com, then store notary credentials:
   ```sh
   xcrun notarytool store-credentials passbar-notary --apple-id <you> --team-id <team id>
   ```
3. `gh auth login`, and make sure `origin` points at the GitHub repo.

## Cutting a release
```sh
git switch main && git pull
scripts/release.sh v0.9.0              # build + sign + notarize + staple, artifacts in build/release/
open build/release/PassBar-0.9.0.dmg   # smoke test on a clean-ish machine/user
scripts/release.sh v0.9.0 --publish    # same, then tag, push and create the GitHub release
```
Artifacts: `PassBar-X.Y.Z.dmg` (primary), `.zip`, `SHA256SUMS.txt`.

## Checklist for every release
- [ ] `swift test` green; manual test against a live Passbolt server (login, search, copy, TOTP, clear)
- [ ] Fresh install and upgrade from the previous release (Keychain items still read)
- [ ] README/SECURITY status notes current; release notes list user-visible changes
- [ ] Notarization passes and `spctl --assess` says "Notarized Developer ID"

## Homebrew tap
After publishing, copy `packaging/homebrew/passbar.rb` into the `cybasoft/homebrew-tap` repo as
`Casks/passbar.rb`, set `version` and the dmg `sha256` from `SHA256SUMS.txt`, then push. Users install
with `brew install --cask cybasoft/tap/passbar`.

## v1.0.0 gate
Don't tag v1.0.0 until the app has run against a real Passbolt instance (the README says it hasn't) and
the app icon no longer resembles Passbolt's logo. Ship `v0.9.0` as the first public beta.
