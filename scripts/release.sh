#!/usr/bin/env bash
# Build, sign (Developer ID), notarize and package PassBar, then optionally publish a GitHub release.
# Usage: scripts/release.sh v1.0.0 [--publish]
# One-time setup: see docs/RELEASING.md (Developer ID cert + `xcrun notarytool store-credentials passbar-notary`).
set -euo pipefail
cd "$(dirname "$0")/.."

TAG="${1:?usage: release.sh vX.Y.Z [--publish]}"
VERSION="${TAG#v}"
TEAM=UA5R4WVYA6
PROFILE=passbar-notary
OUT="build/release"
APP="$OUT/PassBar.app"
ZIP="$OUT/PassBar-$VERSION.zip"
DMG="$OUT/PassBar-$VERSION.dmg"

[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "tag must look like v1.2.3"; exit 1; }
[[ -z "$(git status --porcelain)" ]] || { echo "working tree not clean"; exit 1; }
security find-identity -v -p codesigning | grep -q "Developer ID Application.*($TEAM)" \
  || { echo "no 'Developer ID Application' identity for team $TEAM in keychain"; exit 1; }

./scripts/build-pgp.sh
swift test
xcodegen generate

rm -rf "$OUT" build/DerivedData; mkdir -p "$OUT"
xcodebuild -project PassBar.xcodeproj -scheme PassBar -configuration Release \
  -derivedDataPath build/DerivedData -destination 'generic/platform=macOS' \
  MARKETING_VERSION="$VERSION" CURRENT_PROJECT_VERSION="$(git rev-list --count HEAD)" \
  CODE_SIGN_STYLE=Manual CODE_SIGN_IDENTITY="Developer ID Application" DEVELOPMENT_TEAM=$TEAM \
  OTHER_CODE_SIGN_FLAGS="--timestamp" build
cp -R build/DerivedData/Build/Products/Release/PassBar.app "$APP"
codesign --verify --deep --strict --verbose=2 "$APP"

# Notarize the app, staple, then wrap in a dmg and notarize that too.
ditto -c -k --keepParent "$APP" "$OUT/notarize.zip"
xcrun notarytool submit "$OUT/notarize.zip" --keychain-profile "$PROFILE" --wait
xcrun stapler staple "$APP"
rm "$OUT/notarize.zip"

ditto -c -k --keepParent "$APP" "$ZIP"
hdiutil create -volname "PassBar $VERSION" -srcfolder "$APP" -ov -format UDZO "$DMG"
codesign --sign "Developer ID Application" --timestamp "$DMG"
xcrun notarytool submit "$DMG" --keychain-profile "$PROFILE" --wait
xcrun stapler staple "$DMG"

spctl --assess --type execute --verbose "$APP"
(cd "$OUT" && shasum -a 256 "PassBar-$VERSION.dmg" "PassBar-$VERSION.zip" > SHA256SUMS.txt)
cat "$OUT/SHA256SUMS.txt"

if [[ "${2:-}" == "--publish" ]]; then
  git tag -a "$TAG" -m "PassBar $VERSION"
  git push origin "$TAG"
  gh release create "$TAG" "$DMG" "$ZIP" "$OUT/SHA256SUMS.txt" \
    --title "PassBar $VERSION" --generate-notes --verify-tag
fi
