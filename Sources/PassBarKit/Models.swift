import Foundation

public struct BrowserContext: Equatable, Sendable {
    public let url: URL
    public let browserName: String

    public init(url: URL, browserName: String) {
        self.url = url
        self.browserName = browserName
    }

    public var host: String? { url.host?.lowercased() }
}

/// Searchable, non-secret resource metadata. Held in memory only.
public struct PassboltResource: Identifiable, Equatable, Sendable {
    public let id: String
    public var name: String
    public var username: String
    public var uri: String
    public var uris: [String]
    public var resourceTypeId: String?

    public init(id: String, name: String, username: String = "", uri: String = "", uris: [String] = [],
                resourceTypeId: String? = nil) {
        self.id = id; self.name = name; self.username = username; self.uri = uri
        self.uris = uris.isEmpty && !uri.isEmpty ? [uri] : uris
        self.resourceTypeId = resourceTypeId
    }
}

/// Input for creating a credential. Held in memory only until it is encrypted and sent.
public struct NewResource: Sendable {
    public var name: String
    public var uri: String
    public var uris: [String]
    public var originalUris: [String]
    public var username: String
    public var password: String
    public var totpSecret: String
    public var notes: String
    /// v5 metadata description (visible to everyone with access); `notes` is the encrypted secret note.
    public var description: String

    public init(name: String = "", uri: String = "", uris: [String] = [], username: String = "", password: String = "",
                totpSecret: String = "", notes: String = "", description: String = "") {
        self.name = name; self.uri = uri
        self.uris = uris.isEmpty && !uri.isEmpty ? [uri] : uris
        self.originalUris = uris.isEmpty && !uri.isEmpty ? [uri] : uris
        self.username = username; self.password = password
        self.totpSecret = totpSecret; self.notes = notes; self.description = description
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
    /// v5 only: the metadata description (the secret's `description` is the Note).
    public var metadataDescription: String?

    public init(password: String? = nil, totp: TOTPParameters? = nil, description: String? = nil,
                metadataDescription: String? = nil) {
        self.password = password; self.totp = totp; self.description = description
        self.metadataDescription = metadataDescription
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
            if r.uris.contains(where: { $0.lowercased().contains(q) }) { return 3 }
            return nil
        }
        // Ranked: name prefix, name contains, username, URL. Alphabetical within a rank.
        return sorted.enumerated().compactMap { i, r in score(r).map { (r, $0, i) } }
            .sorted { ($0.1, $0.2) < ($1.1, $1.2) }
            .map { $0.0 }
    }

    /// Ranks resources that belong to the browser's current host.
    public static func matchesBrowser(_ resources: [PassboltResource], context: BrowserContext?) -> [PassboltResource] {
        guard let browserHost = context?.host?.trimmingCharacters(in: .init(charactersIn: ".")), !browserHost.isEmpty else {
            return []
        }
        return resources.compactMap { resource -> (PassboltResource, Int)? in
            var bestScore: Int?
            for uri in resource.uris {
                guard let host = Self.normalizedHost(uri), !host.isEmpty else { continue }
                let score: Int
                if browserHost == host {
                    score = 0
                } else if browserHost.hasSuffix("." + host) || host.hasSuffix("." + browserHost) {
                    score = 1
                } else if Self.registrableDomain(browserHost) == Self.registrableDomain(host) {
                    score = 2
                } else {
                    continue
                }
                bestScore = min(bestScore ?? score, score)
            }
            guard let bestScore else { return nil }
            return (resource, bestScore)
        }
        .sorted {
            if $0.1 != $1.1 { return $0.1 < $1.1 }
            return $0.0.name.localizedCaseInsensitiveCompare($1.0.name) == .orderedAscending
        }
        .map { $0.0 }
    }

    private static func normalizedHost(_ uri: String) -> String? {
        var value = uri.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.hasPrefix("*.") { value = String(value.dropFirst(2)) }
        if value.contains("://") == false { value = "https://" + value }
        guard let host = URL(string: value)?.host?.lowercased()
                .trimmingCharacters(in: .init(charactersIn: ".")),
              !host.isEmpty else { return nil }
        return host
    }

    private static func registrableDomain(_ host: String) -> String {
        let labels = host.split(separator: ".").map(String.init)
        guard labels.count >= 2 else { return host }
        let suffix = labels.suffix(2).joined(separator: ".")
        let publicSuffixes = ["co.uk", "org.uk", "ac.uk", "com.au", "net.au", "co.jp", "co.nz", "com.br", "co.in"]
        if labels.count >= 3, publicSuffixes.contains(suffix) {
            return labels.suffix(3).joined(separator: ".")
        }
        return suffix
    }
}
