import AppKit
import ApplicationServices

/// Puts text into a browser field by focusing it and pasting, which pages treat as real user input.
/// (Setting the accessibility value instead is silent for password fields and skips input events.)
enum FieldEntry {
    private static let eventSource = CGEventSource(stateID: .hidSystemState)

    static func bringToFront(_ app: NSRunningApplication) -> Bool {
        app.activate()
        let deadline = Date().addingTimeInterval(1.0)
        while Date() < deadline {
            if NSWorkspace.shared.frontmostApplication?.processIdentifier == app.processIdentifier { return true }
            Thread.sleep(forTimeInterval: 0.05)
        }
        return false
    }

    /// Accessibility focus only moves the page's own focus; the web view must also own the keyboard.
    static func focusPage(_ webArea: AXUIElement) {
        AXUIElementSetAttributeValue(webArea, kAXFocusedAttribute as CFString, kCFBooleanTrue)
        Thread.sleep(forTimeInterval: 0.1)
    }

    static func enter(_ text: String, in element: AXUIElement) {
        AXUIElementSetAttributeValue(element, kAXFocusedAttribute as CFString, kCFBooleanTrue)
        Thread.sleep(forTimeInterval: 0.3)
        dismissPopupMenu()
        post(keyCode: 0, flags: .maskCommand)   // select all, so existing text is replaced
        Thread.sleep(forTimeInterval: 0.05)
        paste(text)
    }

    /// Browsers open their own password menu when a login field gains focus, and it swallows keystrokes.
    private static func dismissPopupMenu() {
        var focused: CFTypeRef?
        guard AXUIElementCopyAttributeValue(AXUIElementCreateSystemWide(), kAXFocusedUIElementAttribute as CFString, &focused) == .success,
              let focused, CFGetTypeID(focused) == AXUIElementGetTypeID(),
              ["AXMenu", "AXMenuItem"].contains(PageFields.string(focused as! AXUIElement, kAXRoleAttribute)) else { return }
        post(keyCode: 53, flags: [])   // Escape
        Thread.sleep(forTimeInterval: 0.15)
    }

    /// Pastes `text` and puts the previous clipboard back. The value is marked concealed for clipboard managers.
    private static func paste(_ text: String) {
        let board = NSPasteboard.general
        let saved = board.pasteboardItems?.map { item -> NSPasteboardItem in
            let copy = NSPasteboardItem()
            for type in item.types { if let data = item.data(forType: type) { copy.setData(data, forType: type) } }
            return copy
        }
        board.clearContents()
        board.setString(text, forType: .string)
        board.setData(Data(), forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
        post(keyCode: 9, flags: .maskCommand)   // Cmd+V
        Thread.sleep(forTimeInterval: 0.25)
        board.clearContents()
        if let saved { board.writeObjects(saved) }
    }

    private static func post(keyCode: CGKeyCode, flags: CGEventFlags) {
        for down in [true, false] {
            let event = CGEvent(keyboardEventSource: eventSource, virtualKey: keyCode, keyDown: down)
            event?.flags = flags
            event?.post(tap: .cghidEventTap)
        }
    }
}
