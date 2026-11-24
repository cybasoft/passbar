import AppKit
import ApplicationServices
import PassBarKit

/// Fills the browser's login or one-time-code fields. Uses the macOS Accessibility API, so it works with any
/// browser that exposes its page to accessibility, needs one system permission and no browser setup.
enum BrowserAutofill {
    /// Returns nil on success, otherwise a user-facing message. `beforeTyping` runs once the fields are found
    /// (used to dismiss the popover so the browser can take focus).
    static func fill(context: BrowserContext, credential: FillCredential, beforeTyping: () -> Void) -> String? {
        guard let bundleId = context.bundleIdentifier,
              let app = NSRunningApplication.runningApplications(withBundleIdentifier: bundleId).first else {
            return "Open a supported browser tab to fill this credential."
        }
        guard AXIsProcessTrusted() else {
            requestAccessibilityOnce()
            return AppModel.accessibilityRequiredMessage
        }

        let page: PageFields.Page
        switch PageFields.locate(in: AXUIElementCreateApplication(app.processIdentifier), host: context.host) {
        case .found(let found): page = found
        case .pageChanged: return "The page changed. Reopen PassBar on the page you want to fill."
        case .none: return "No login fields found on this page."
        }
        if page.oneTimeCode != nil, credential.oneTimeCode == nil {
            return "This page asks for a code, but this credential has no authenticator key."
        }

        beforeTyping()
        guard FieldEntry.bringToFront(app) else { return "Couldn't switch to \(context.browserName)." }
        FieldEntry.focusPage(page.webArea)

        if let field = page.oneTimeCode, let code = credential.oneTimeCode { FieldEntry.enter(code, in: field) }
        if let field = page.username, !credential.username.isEmpty { FieldEntry.enter(credential.username, in: field) }
        if let field = page.password, !credential.password.isEmpty { FieldEntry.enter(credential.password, in: field) }
        return nil
    }

    private static var requestedAccessibility = false

    /// The system prompt registers PassBar in the Accessibility list; repeating it on every click is just noise.
    private static func requestAccessibilityOnce() {
        guard !requestedAccessibility else { return }
        requestedAccessibility = true
        let options = [kAXTrustedCheckOptionPrompt.takeUnretainedValue(): true] as CFDictionary
        _ = AXIsProcessTrustedWithOptions(options)
    }
}
