import Foundation

/// Searchable, non-secret resource metadata. Held in memory only.
public struct PassboltResource: Identifiable, Equatable, Sendable {
    public let id: String
    public var name: String
    public var username: String
    public var uri: String
    public var resourceTypeId: String?

    public init(id: String, name: String, username: String = "", uri: String = "", resourceTypeId: String? = nil) {
        self.id = id; self.name = name; self.username = username; self.uri = uri
        self.resourceTypeId = resourceTypeId
    }
}

/// Input for creating a credential. Held in memory only until it is encrypted and sent.
public struct NewResource: Sendable {
    public var name: String
    public var uri: String
    public var username: String
    public var password: String
    public var totpSecret: String
    public var notes: String

    public init(name: String = "", uri: String = "", username: String = "", password: String = "",
                totpSecret: String = "", notes: String = "") {
        self.name = name; self.uri = uri; self.username = username; self.password = password
        self.totpSecret = totpSecret; self.notes = notes
    }
}

public struct TOTPParameters: Equatable, Sendable {
    public var secretKey: String
    public var algorithm: String
    public var digits: Int
    public var period: Int

    public init(secretKey: String, algorithm: String = "SHA1", digits: Int = 6, period: Int = 30) {
        self.secretKey = secretKey; self.algorithm = algorithm; self.digits = digits; self.period = period
    }
}

/// SECURITY CRITICAL: decrypted credential material. Never log, persist or transmit.
public struct ResourceSecret: Equatable, Sendable {
    public var password: String?
    public var totp: TOTPParameters?
    public var description: String?

    public init(password: String? = nil, totp: TOTPParameters? = nil, description: String? = nil) {
        self.password = password; self.totp = totp; self.description = description
    }
}

/// Pure, in-memory search over resource metadata (name, username, URL).
public enum ResourceSearch {
    /// Maximum rows shown for the default view and for search results.
    public static let listLimit = 25

    public static func filter(_ resources: [PassboltResource], query: String) -> [PassboltResource] {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        let sorted = resources.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        guard !q.isEmpty else { return sorted }
        func score(_ r: PassboltResource) -> Int? {
            let name = r.name.lowercased()
            if name.hasPrefix(q) { return 0 }
            if name.contains(q) { return 1 }
            if r.username.lowercased().contains(q) { return 2 }
            if r.uri.lowercased().contains(q) { return 3 }
            return nil
        }
        // Ranked: name prefix, name contains, username, URL. Alphabetical within a rank.
        return sorted.enumerated().compactMap { i, r in score(r).map { (r, $0, i) } }
            .sorted { ($0.1, $0.2) < ($1.1, $1.2) }
            .map { $0.0 }
    }
}
