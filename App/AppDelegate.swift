import SwiftUI
import Combine
import PassboltKit

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, NSPopoverDelegate {
    private var statusItem: NSStatusItem!
    private let popover = NSPopover()
    private var settingsWindow: NSWindow?
    private var cancellables = Set<AnyCancellable>()
    private let hotKey = HotKeyManager()

    let model: AppModel = {
        let prefs = Preferences()
        return AppModel(preferences: prefs, store: KeychainSecretStore(), authenticator: SystemAuthenticator(),
                        clipboard: ClipboardManager(pasteboard: SystemPasteboard()),
                        makeClient: { url, uid, fp in
                            try PassboltAPIClient(serverURL: url, userId: uid, pinnedFingerprint: fp,
                                                  transport: URLSessionTransport(), pgp: GopenPGPProvider())
                        })
    }()

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        statusItem.button?.target = self
        statusItem.button?.action = #selector(togglePopover)
        updateIcon()

        popover.behavior = .transient
        popover.delegate = self
        popover.contentSize = NSSize(width: 400, height: 460)
        popover.contentViewController = NSHostingController(rootView: RootView(model: model, actions: actions))

        model.$state.sink { [weak self] _ in self?.updateIcon() }.store(in: &cancellables)
        model.preferences.$hotKey.sink { [weak self] in self?.registerHotKey($0) }.store(in: &cancellables)
    }

    func applicationWillTerminate(_ notification: Notification) {
        MainActor.assumeIsolated { model.prepareForTermination() }
    }

    private var actions: AppActions {
        AppActions(close: { [weak self] in self?.popover.performClose(nil) },
                   openSettings: { [weak self] in self?.showSettings() },
                   quit: { NSApp.terminate(nil) })
    }

    /// PassBar glyph as a template image (adapts to light/dark). Dimmed while locked.
    private func updateIcon() {
        let img = NSImage(named: "MenuBarIcon")
        img?.size = NSSize(width: 24, height: 24 * 44 / 92)
        img?.isTemplate = true
        statusItem.button?.image = img
        statusItem.button?.alphaValue = model.state == .unlocked ? 1.0 : 0.45
        statusItem.button?.setAccessibilityLabel(model.state == .unlocked ? "PassBar (unlocked)" : "PassBar (locked)")
    }

    private func registerHotKey(_ preset: String) {
        hotKey.register(preset: preset) { [weak self] in self?.togglePopover() }
    }

    @objc func togglePopover() {
        guard let button = statusItem.button else { return }
        if popover.isShown { popover.performClose(nil); return }
        NSApp.activate(ignoringOtherApps: true)
        popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        popover.contentViewController?.view.window?.makeKey()
    }

    func popoverDidClose(_ notification: Notification) {
        model.clearDetail()   // keep decrypted data in memory only while visible
    }

    func showSettings() {
        popover.performClose(nil)
        if settingsWindow == nil {
            let w = NSWindow(contentViewController: NSHostingController(rootView: SettingsView(model: model)))
            w.title = "Passbolt Settings"
            w.styleMask = [.titled, .closable]
            w.isReleasedWhenClosed = false
            settingsWindow = w
        }
        NSApp.activate(ignoringOtherApps: true)
        settingsWindow?.center()
        settingsWindow?.makeKeyAndOrderFront(nil)
    }
}

struct AppActions {
    var close: () -> Void
    var openSettings: () -> Void
    var quit: () -> Void
}
