import SwiftUI
import Combine
import PassBarKit

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, NSPopoverDelegate {
    private var statusItem: NSStatusItem!
    private let popover = NSPopover()
    private var settingsWindow: NSWindow?
    private var cancellables = Set<AnyCancellable>()
    private let hotKey = HotKeyManager()

    let model: AppModel = {
        let legacy = Bundle.main.bundleIdentifier.map(Preferences.legacySandboxPlist(bundleIdentifier:))
        let prefs = Preferences(legacyPlist: legacy)
        let model = AppModel(preferences: prefs, store: KeychainSecretStore(), authenticator: SystemAuthenticator(),
                        clipboard: ClipboardManager(pasteboard: SystemPasteboard()),
                        detectBrowserContext: { BrowserContextDetector.detect(bundleIdentifier: $0) },
                        makeClient: { url, uid, fp in
                            try PassboltAPIClient(serverURL: url, userId: uid, pinnedFingerprint: fp,
                                                  transport: URLSessionTransport(), pgp: GopenPGPProvider())
                        })
        return model
    }()

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        statusItem.button?.target = self
        statusItem.button?.action = #selector(togglePopover)
        updateIcon(model.state)

        popover.behavior = .transient
        popover.delegate = self
        popover.contentSize = NSSize(width: 360, height: 480)
        popover.contentViewController = NSHostingController(rootView: RootView(model: model, actions: actions))

        model.fillBrowser = { [weak self] context, username, password in
            BrowserAutofill.fill(context: context, username: username, password: password) {
                DispatchQueue.main.sync { self?.popover.performClose(nil) }
            }
        }
        model.$state.sink { [weak self] in self?.updateIcon($0) }.store(in: &cancellables)
        model.preferences.$hotKey.sink { [weak self] in self?.registerHotKey($0) }.store(in: &cancellables)
    }

    func applicationWillTerminate(_ notification: Notification) {
        MainActor.assumeIsolated { model.prepareForTermination() }
    }

    private var actions: AppActions {
        AppActions(close: { [weak self] in self?.popover.performClose(nil) },
                   openSettings: { [weak self] in self?.showSettings() },
                   openServer: { [weak self] in self?.openServer() },
                   openBrowserAutomation: { [weak self] in self?.openBrowserAutomation() },
                   openAccessibility: { [weak self] in self?.openAccessibility() },
                   quit: { NSApp.terminate(nil) })
    }

    private func openBrowserAutomation() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Automation") {
            NSWorkspace.shared.open(url)
        }
    }

    private func openAccessibility() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility") {
            NSWorkspace.shared.open(url)
        }
    }

    private func openServer() {
        guard let url = URL(string: model.preferences.serverURL), url.scheme == "https" else { return }
        popover.performClose(nil)
        NSWorkspace.shared.open(url)
    }

    /// PassBar glyph as a template image (adapts to light/dark). Dimmed while locked.
    private func updateIcon(_ state: LockState) {
        let img = NSImage(named: "MenuBarIcon")
        img?.size = NSSize(width: 18, height: 18)
        img?.isTemplate = true
        statusItem.button?.image = img
        statusItem.button?.alphaValue = state == .unlocked ? 1.0 : 0.45
        statusItem.button?.setAccessibilityLabel(state == .unlocked ? "PassBar (unlocked)" : "PassBar (locked)")
    }

    private func registerHotKey(_ preset: String) {
        hotKey.register(preset: preset) { [weak self] in self?.togglePopover() }
    }

    @objc func togglePopover() {
        guard let button = statusItem.button else { return }
        if popover.isShown { popover.performClose(nil); return }
        let front = NSWorkspace.shared.frontmostApplication?.bundleIdentifier
        let browserBundleIdentifier = front == Bundle.main.bundleIdentifier ? nil : front
        model.refreshBrowserContext(bundleIdentifier: browserBundleIdentifier)
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
            w.title = "PassBar Settings"
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
    var openServer: () -> Void
    var openBrowserAutomation: () -> Void
    var openAccessibility: () -> Void
    var quit: () -> Void
}
