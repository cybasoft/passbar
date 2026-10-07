cask "passbar" do
  version "0.9.0"
  sha256 "REPLACE_WITH_DMG_SHA256"

  url "https://github.com/cybasoft/passbar/releases/download/v#{version}/PassBar-#{version}.dmg"
  name "PassBar"
  desc "Menu-bar client for Passbolt API"
  homepage "https://github.com/cybasoft/passbar"

  livecheck do
    url :url
    strategy :github_latest
  end

  depends_on macos: ">= :sonoma"

  app "PassBar.app"

  zap trash: [
    "~/Library/Containers/com.cybasoft.passbar",
    "~/Library/Preferences/com.cybasoft.passbar.plist",
  ]
end
