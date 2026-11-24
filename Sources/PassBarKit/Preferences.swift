import Foundation

/// Non-secret settings only (UserDefaults). Secrets live in the Keychain.
public final class Preferences: ObservableObject {
    private let defaults: UserDefaults

    @Published public var serverURL: String { didSet { defaults.set(serverURL, forKey: "serverURL") } }
    @Published public var userId: String { didSet { defaults.set(userId, forKey: "userId") } }
    /// Server key fingerprint trusted on first login (public information).
    @Published public var serverFingerprint: String { didSet { defaults.set(serverFingerprint, forKey: "serverFingerprint") } }
    /// Fingerprint of the user's own key, for display only.
    @Published public var keyFingerprint: String { didSet { defaults.set(keyFingerprint, forKey: "keyFingerprint") } }
    @Published public var clipboardTimeout: Double { didSet { defaults.set(clipboardTimeout, forKey: "clipboardTimeout") } }
    /// Minutes of inactivity before locking; 0 = never.
    @Published public var autoLockMinutes: Double { didSet { defaults.set(autoLockMinutes, forKey: "autoLockMinutes") } }
    @Published public var hotKey: String { didSet { defaults.set(hotKey, forKey: "hotKey") } }
    /// Most recently opened resource IDs (non-secret), newest first.
    public private(set) var recentResourceIds: [String] { didSet { defaults.set(recentResourceIds, forKey: "recentResourceIds") } }

    private static let migratedKeys = ["serverURL", "userId", "serverFingerprint", "keyFingerprint",
                                       "clipboardTimeout", "autoLockMinutes", "hotKey", "recentResourceIds"]

    /// Where earlier, sandboxed releases kept their settings.
    public static func legacySandboxPlist(bundleIdentifier: String) -> URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Containers/\(bundleIdentifier)/Data/Library/Preferences/\(bundleIdentifier).plist")
    }

    /// Copies settings from `legacyPlist` once, only when none are set yet.
    public init(defaults: UserDefaults = .standard, legacyPlist: URL? = nil) {
        if let legacyPlist, defaults.object(forKey: "serverURL") == nil,
           let old = NSDictionary(contentsOf: legacyPlist) as? [String: Any] {
            for key in Self.migratedKeys { if let value = old[key] { defaults.set(value, forKey: key) } }
        }
        self.defaults = defaults
        serverURL = defaults.string(forKey: "serverURL") ?? ""
        userId = defaults.string(forKey: "userId") ?? ""
        serverFingerprint = defaults.string(forKey: "serverFingerprint") ?? ""
        keyFingerprint = defaults.string(forKey: "keyFingerprint") ?? ""
        clipboardTimeout = defaults.object(forKey: "clipboardTimeout") as? Double ?? 30
        autoLockMinutes = defaults.object(forKey: "autoLockMinutes") as? Double ?? 5
        hotKey = defaults.string(forKey: "hotKey") ?? "ctrl-opt-space"
        recentResourceIds = defaults.stringArray(forKey: "recentResourceIds") ?? []
    }

    public func recordRecent(_ id: String, limit: Int = ResourceSearch.listLimit) {
        recentResourceIds = Array(([id] + recentResourceIds.filter { $0 != id }).prefix(limit))
    }

    public func resetAccount() {
        serverURL = ""
        userId = ""
        serverFingerprint = ""; keyFingerprint = ""; recentResourceIds = []
    }
}
