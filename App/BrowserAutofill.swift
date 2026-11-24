import AppKit
import ApplicationServices
import PassBarKit

/// Fills the browser's login fields through the macOS Accessibility API and synthesized key events.
/// Works with any browser that exposes its page to accessibility; needs one system permission and no browser setup.
enum BrowserAutofill {
    private struct Field {
        let element: AXUIElement
        let isPassword: Bool
        let label: String
    }

    private struct Target {
        let username: AXUIElement?
        let password: AXUIElement?
        let pageURL: URL?
    }

    /// Returns nil on success, otherwise a user-facing message. `beforeTyping` runs once the fields are found
    /// (used to dismiss the popover so the browser can take focus).
    static func fill(context: BrowserContext, username: String, password: String,
                     beforeTyping: () -> Void) -> String? {
        guard let bundleId = context.bundleIdentifier,
              let app = NSRunningApplication.runningApplications(withBundleIdentifier: bundleId).first else {
            return "Open a supported browser tab to fill this credential."
        }
        let options = [kAXTrustedCheckOptionPrompt.takeUnretainedValue(): true] as CFDictionary
        guard AXIsProcessTrustedWithOptions(options) else {
            return AppModel.accessibilityRequiredMessage
        }

        let appElement = AXUIElementCreateApplication(app.processIdentifier)
        // Chromium only builds its accessibility tree for the page once asked.
        AXUIElementSetAttributeValue(appElement, "AXManualAccessibility" as CFString, kCFBooleanTrue)

        guard let target = locateFields(in: appElement) else { return "No login fields found on this page." }
        if let pageHost = target.pageURL?.host?.lowercased(), pageHost != context.host {
            return "The page changed. Reopen PassBar on the page you want to fill."
        }

        beforeTyping()
        guard bringToFront(app) else { return "Couldn't switch to \(context.browserName)." }

        if let element = target.username, !username.isEmpty { focusAndType(username, in: element) }
        if let element = target.password, !password.isEmpty { focusAndType(password, in: element) }
        return nil
    }

    // MARK: Finding fields

    /// The page tree can appear a moment after accessibility is enabled, so retry briefly.
    private static func locateFields(in app: AXUIElement) -> Target? {
        let deadline = Date().addingTimeInterval(2.5)
        repeat {
            if let window = copy(app, kAXMainWindowAttribute) ?? firstWindow(of: app),
               let web = findWebArea(in: window) {
                var fields: [Field] = []
                var budget = 4000
                collectFields(in: web, into: &fields, budget: &budget)
                if let target = choose(from: fields, pageURL: pageURL(of: web)) { return target }
            }
            Thread.sleep(forTimeInterval: 0.15)
        } while Date() < deadline
        return nil
    }

    private static func choose(from fields: [Field], pageURL: URL?) -> Target? {
        if let pw = fields.firstIndex(where: \.isPassword) {
            let user = fields[..<pw].last(where: { !$0.isPassword })
            return Target(username: user?.element, password: fields[pw].element, pageURL: pageURL)
        }
        // Multi-step login: only the identifier step is on screen.
        let candidates = fields.filter { !$0.isPassword }
        let user = candidates.first { $0.label.range(of: "user|email|login|account", options: [.regularExpression, .caseInsensitive]) != nil }
            ?? candidates.first
        return user.map { Target(username: $0.element, password: nil, pageURL: pageURL) }
    }

    private static func firstWindow(of app: AXUIElement) -> AXUIElement? {
        var value: CFTypeRef?
        guard AXUIElementCopyAttributeValue(app, kAXWindowsAttribute as CFString, &value) == .success,
              let windows = value as? [AXUIElement] else { return nil }
        return windows.first
    }

    private static func findWebArea(in root: AXUIElement) -> AXUIElement? {
        var queue = [root]
        var visited = 0
        while !queue.isEmpty, visited < 3000 {
            let element = queue.removeFirst()
            visited += 1
            if string(element, kAXRoleAttribute) == "AXWebArea" { return element }
            queue.append(contentsOf: children(of: element))
        }
        return nil
    }

    /// Depth-first so fields come back in document order.
    private static func collectFields(in element: AXUIElement, into fields: inout [Field], budget: inout Int) {
        guard budget > 0 else { return }
        budget -= 1
        let role = string(element, kAXRoleAttribute)
        let subrole = string(element, kAXSubroleAttribute)
        if role == "AXTextField" || role == "AXComboBox" {
            if subrole != "AXSearchField", isUsable(element) {
                let label = [kAXTitleAttribute, kAXDescriptionAttribute, kAXPlaceholderValueAttribute, kAXIdentifierAttribute]
                    .compactMap { string(element, $0) }.joined(separator: " ")
                fields.append(Field(element: element, isPassword: subrole == "AXSecureTextField", label: label))
            }
            return
        }
        for child in children(of: element) { collectFields(in: child, into: &fields, budget: &budget) }
    }

    private static func isUsable(_ element: AXUIElement) -> Bool {
        var enabled: CFTypeRef?
        if AXUIElementCopyAttributeValue(element, kAXEnabledAttribute as CFString, &enabled) == .success,
           (enabled as? Bool) == false { return false }
        var raw: CFTypeRef?
        guard AXUIElementCopyAttributeValue(element, kAXSizeAttribute as CFString, &raw) == .success,
              let raw, CFGetTypeID(raw) == AXValueGetTypeID() else { return true }
        var size = CGSize.zero
        AXValueGetValue(raw as! AXValue, .cgSize, &size)
        return size.width > 0 && size.height > 0
    }

    private static func pageURL(of webArea: AXUIElement) -> URL? {
        var value: CFTypeRef?
        guard AXUIElementCopyAttributeValue(webArea, kAXURLAttribute as CFString, &value) == .success else { return nil }
        return value as? URL
    }

    private static func children(of element: AXUIElement) -> [AXUIElement] {
        var value: CFTypeRef?
        guard AXUIElementCopyAttributeValue(element, kAXChildrenAttribute as CFString, &value) == .success else { return [] }
        return value as? [AXUIElement] ?? []
    }

    private static func string(_ element: AXUIElement, _ attribute: String) -> String? {
        var value: CFTypeRef?
        guard AXUIElementCopyAttributeValue(element, attribute as CFString, &value) == .success else { return nil }
        return value as? String
    }

    private static func copy(_ element: AXUIElement, _ attribute: String) -> AXUIElement? {
        var value: CFTypeRef?
        guard AXUIElementCopyAttributeValue(element, attribute as CFString, &value) == .success,
              let value, CFGetTypeID(value) == AXUIElementGetTypeID() else { return nil }
        return (value as! AXUIElement)
    }

    // MARK: Typing

    private static func bringToFront(_ app: NSRunningApplication) -> Bool {
        app.activate()
        let deadline = Date().addingTimeInterval(1.0)
        while Date() < deadline {
            if NSWorkspace.shared.frontmostApplication?.processIdentifier == app.processIdentifier { return true }
            Thread.sleep(forTimeInterval: 0.05)
        }
        return false
    }

    private static func focusAndType(_ text: String, in element: AXUIElement) {
        AXUIElementSetAttributeValue(element, kAXFocusedAttribute as CFString, kCFBooleanTrue)
        Thread.sleep(forTimeInterval: 0.1)
        post(keyCode: 0, flags: .maskCommand)   // select all, so existing text is replaced
        Thread.sleep(forTimeInterval: 0.03)
        for chunk in chunks(of: text) {
            for down in [true, false] {
                let event = CGEvent(keyboardEventSource: nil, virtualKey: 0, keyDown: down)
                event?.keyboardSetUnicodeString(stringLength: chunk.count, unicodeString: chunk)
                event?.post(tap: .cgSessionEventTap)
            }
            Thread.sleep(forTimeInterval: 0.01)
        }
    }

    private static func post(keyCode: CGKeyCode, flags: CGEventFlags) {
        for down in [true, false] {
            let event = CGEvent(keyboardEventSource: nil, virtualKey: keyCode, keyDown: down)
            event?.flags = flags
            event?.post(tap: .cgSessionEventTap)
        }
    }

    /// UTF-16 chunks that never split a surrogate pair.
    private static func chunks(of text: String, size: Int = 16) -> [[UniChar]] {
        var result: [[UniChar]] = []
        var current: [UniChar] = []
        for scalar in text.unicodeScalars {
            let units = Array(String(scalar).utf16)
            if current.count + units.count > size { result.append(current); current = [] }
            current += units
        }
        if !current.isEmpty { result.append(current) }
        return result
    }
}
