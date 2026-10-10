# Changelog

## 0.9.2

- Support authenticator-app (TOTP) multi-factor authentication.
- Lock the vault when Passbolt authentication expires.
- Clear the saved server URL and user ID when clearing credentials.

## 0.9.1

- Edit supported records.
- Separate secret notes from the resource description.
- Improve the record detail view and preserve in-progress creation when the popover closes.
- Correct the menu-bar icon's locked and unlocked state.

## 0.9.0

First public beta. Search and copy credentials from a Passbolt (v5, RSA key) vault via a macOS
menu-bar popover. Not yet verified against a live Passbolt instance; see SECURITY.md.
