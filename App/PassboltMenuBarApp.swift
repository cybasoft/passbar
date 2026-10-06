import SwiftUI

@main
struct PassboltMenuBarApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    // The UI lives in an NSStatusItem + NSPopover (see AppDelegate) so the popover
    // can be opened from a global shortcut. The Settings window is managed there too.
    var body: some Scene {
        Settings { EmptyView() }
    }
}
