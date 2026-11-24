# Changelog

## 1.0.3

- Fix autofill in Safari and Chrome: fields are now filled by pasting, so pages see real input.
- Fill authenticator-code (2FA) fields with the credential's current code.
- Prompt for Accessibility once instead of on every click.

## 1.0.2

- Suggest credentials matching the current browser tab.
- Click a credential to fill the login fields on the current page, or use "Use on this page" from its details. Requires the Accessibility permission.
- PassBar is no longer sandboxed, which macOS requires for Accessibility. Existing settings are migrated automatically.

## 1.0.1

- Remember multi-factor authentication for 30 days when requested.
- Automatically refresh expired authentication sessions.

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
