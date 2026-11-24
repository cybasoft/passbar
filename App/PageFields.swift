import ApplicationServices
import Foundation

/// Finds login and one-time-code fields in a browser page through the Accessibility tree.
enum PageFields {
    struct Page {
        let webArea: AXUIElement
        let username: AXUIElement?
        let password: AXUIElement?
        let oneTimeCode: AXUIElement?
    }

    enum Lookup {
        case found(Page)
        /// Fields exist, but on a different page than the one PassBar was opened over.
        case pageChanged
        case none
    }

    private struct Field {
        let element: AXUIElement
        let isPassword: Bool
        let label: String
    }

    private static let codePattern = "code|otp|authenticator|2fa|verif|token|one.?time|passcode|security"
    private static let userPattern = "user|email|login|account|phone"

    /// Chromium builds a page's accessibility tree on first use, so keep looking for a few seconds.
    static func locate(in app: AXUIElement, host: String?, timeout: TimeInterval = 4) -> Lookup {
        let deadline = Date().addingTimeInterval(timeout)
        var mismatched = false
        repeat {
            guard let window = copy(app, kAXMainWindowAttribute) ?? firstWindow(of: app) else {
                Thread.sleep(forTimeInterval: 0.15); continue
            }
            var fallback: Page?
            for web in webAreas(in: window) {
                var fields: [Field] = []
                var budget = 4000
                collect(in: web, into: &fields, budget: &budget)
                guard let page = page(from: fields, webArea: web) else { continue }
                guard let pageHost = pageURL(of: web)?.host?.lowercased() else { fallback = fallback ?? page; continue }
                if pageHost == host { return .found(page) }
                mismatched = true
            }
            if let fallback { return .found(fallback) }
            Thread.sleep(forTimeInterval: 0.15)
        } while Date() < deadline
        return mismatched ? .pageChanged : .none
    }

    private static func page(from fields: [Field], webArea: AXUIElement) -> Page? {
        if let pw = fields.firstIndex(where: \.isPassword) {
            let user = fields[..<pw].last(where: { !$0.isPassword })
            return Page(webArea: webArea, username: user?.element, password: fields[pw].element, oneTimeCode: nil)
        }
        func matches(_ field: Field, _ pattern: String) -> Bool {
            field.label.range(of: pattern, options: [.regularExpression, .caseInsensitive]) != nil
        }
        if let code = fields.first(where: { matches($0, codePattern) && !matches($0, userPattern) }) {
            return Page(webArea: webArea, username: nil, password: nil, oneTimeCode: code.element)
        }
        // Multi-step login: only the identifier step is on screen.
        guard let user = fields.first(where: { matches($0, userPattern) }) ?? fields.first else { return nil }
        return Page(webArea: webArea, username: user.element, password: nil, oneTimeCode: nil)
    }

    // MARK: Walking the tree

    private static func firstWindow(of app: AXUIElement) -> AXUIElement? {
        var value: CFTypeRef?
        guard AXUIElementCopyAttributeValue(app, kAXWindowsAttribute as CFString, &value) == .success else { return nil }
        return (value as? [AXUIElement])?.first
    }

    /// Browsers can hold several (side panels, extension frames); the page itself is usually the first.
    private static func webAreas(in root: AXUIElement) -> [AXUIElement] {
        var found: [AXUIElement] = []
        var queue = [root]
        var visited = 0
        while !queue.isEmpty, visited < 5000 {
            let element = queue.removeFirst()
            visited += 1
            if string(element, kAXRoleAttribute) == "AXWebArea" { found.append(element); continue }
            queue.append(contentsOf: children(of: element))
        }
        return found
    }

    /// Depth-first so fields come back in document order.
    private static func collect(in element: AXUIElement, into fields: inout [Field], budget: inout Int) {
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
        for child in children(of: element) { collect(in: child, into: &fields, budget: &budget) }
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

    static func children(of element: AXUIElement) -> [AXUIElement] {
        var value: CFTypeRef?
        guard AXUIElementCopyAttributeValue(element, kAXChildrenAttribute as CFString, &value) == .success else { return [] }
        return value as? [AXUIElement] ?? []
    }

    static func string(_ element: AXUIElement, _ attribute: String) -> String? {
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
}
