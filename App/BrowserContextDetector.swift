import AppKit
import PassBarKit

struct BrowserContextDetector {
    struct Browser {
        let bundleId: String
        let name: String
        let isSafari: Bool
        let script: String

        init(_ bundleId: String, _ name: String, safari: Bool = false) {
            self.bundleId = bundleId
            self.name = name
            self.isSafari = safari
            let tab = safari ? "current tab" : "active tab"
            script = """
            tell application id "\(bundleId)"
                if (count of windows) > 0 then
                    return URL of \(tab) of front window
                end if
            end tell
            """
        }
    }

    static let browsers: [Browser] = [
        Browser("com.apple.Safari", "Safari", safari: true),
        Browser("com.apple.SafariTechnologyPreview", "Safari Technology Preview", safari: true),
        Browser("com.google.Chrome", "Chrome"),
        Browser("com.google.Chrome.beta", "Chrome Beta"),
        Browser("com.google.Chrome.canary", "Chrome Canary"),
        Browser("org.chromium.Chromium", "Chromium"),
        Browser("com.brave.Browser", "Brave"),
        Browser("com.microsoft.edgemac", "Microsoft Edge"),
        Browser("company.thebrowser.Browser", "Arc"),
        Browser("com.vivaldi.Vivaldi", "Vivaldi"),
        Browser("com.operasoftware.Opera", "Opera"),
    ]

    static func detect(bundleIdentifier: String?) -> BrowserContext? {
        let running = Set(NSWorkspace.shared.runningApplications.compactMap(\.bundleIdentifier))
        // The browser that was frontmost when PassBar opened goes first.
        let ordered = browsers.filter { $0.bundleId == bundleIdentifier }
            + browsers.filter { $0.bundleId != bundleIdentifier }

        for browser in ordered where running.contains(browser.bundleId) {
            guard let urlText = runAppleScript(browser.script, label: browser.name).value,
                  let url = URL(string: urlText),
                  ["http", "https"].contains(url.scheme?.lowercased()) else { continue }
            return BrowserContext(url: url, browserName: browser.name, bundleIdentifier: browser.bundleId)
        }
        return nil
    }

    struct ScriptOutcome {
        var value: String?
        var errorCode: Int?
    }

    /// Runs in-process so the Automation permission belongs to PassBar. The source is never logged.
    static func runAppleScript(_ source: String, label: String, timeout: TimeInterval = 2.0) -> ScriptOutcome {
        let result = Box()
        let done = DispatchSemaphore(value: 0)
        DispatchQueue.global(qos: .userInitiated).async {
            var error: NSDictionary?
            let descriptor = NSAppleScript(source: source)?.executeAndReturnError(&error)
            if let error {
                let code = (error[NSAppleScript.errorNumber] as? Int) ?? 0
                result.outcome.errorCode = code
                NSLog("PassBar browser script: %@ failed (%d)", label, code)
            }
            let text = descriptor?.stringValue?.trimmingCharacters(in: .whitespacesAndNewlines)
            result.outcome.value = text.flatMap { $0.isEmpty ? nil : $0 }
            done.signal()
        }
        // A first-run Automation prompt can block the script; don't hold up the UI for it.
        guard done.wait(timeout: .now() + timeout) == .success else { return ScriptOutcome(value: nil, errorCode: -1) }
        return result.outcome
    }

    private final class Box: @unchecked Sendable {
        var outcome = ScriptOutcome()
    }
}
