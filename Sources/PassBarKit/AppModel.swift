import Foundation
import Combine

public enum LockState: Equatable { case unconfigured, locked, unlocking, unlocked }

/// Everything shown for the selected resource. Cleared as soon as the user leaves it.
public struct ResourceDetail {
    public let resource: PassboltResource
    public let secret: ResourceSecret
}

/// View-model layer. Independent of SwiftUI so it can be unit tested.
@MainActor
public final class AppModel: ObservableObject {
    @Published public private(set) var state: LockState
    @Published public var query = "" { didSet { refreshResults() } }
    @Published public private(set) var results: [PassboltResource] = []
    @Published public private(set) var detail: ResourceDetail?
    @Published public private(set) var errorMessage: String?
    @Published public private(set) var isLoading = false
    @Published public private(set) var copiedField: String?

    public let preferences: Preferences
    private let store: SecretStore
    private let authenticator: LocalAuthenticator
    private let clipboard: ClipboardManager
    private let makeClient: (URL, String, String?) throws -> PassboltClient
    private var client: PassboltClient?
    private var lastActivity = Date()
    private var inactivityTask: Task<Void, Never>?

    public init(preferences: Preferences, store: SecretStore, authenticator: LocalAuthenticator,
                clipboard: ClipboardManager, makeClient: @escaping (URL, String, String?) throws -> PassboltClient) {
        self.preferences = preferences; self.store = store; self.authenticator = authenticator
        self.clipboard = clipboard; self.makeClient = makeClient
        let configured = (try? store.get(.privateKey)) != nil && !preferences.serverURL.isEmpty
        state = configured ? .locked : .unconfigured
    }

    // MARK: Setup

    /// First-time setup. Secrets are only persisted after login succeeds.
    public func configure(serverURL: String, userId: String, privateKey: String, passphrase: String) async {
        errorMessage = nil
        guard let url = URL(string: serverURL.trimmingCharacters(in: .whitespacesAndNewlines)) else {
            errorMessage = PassboltError.invalidServerURL.localizedDescription; return
        }
        guard url.scheme == "https" else { errorMessage = PassboltError.insecureServerURL.localizedDescription; return }
        let uid = userId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard UUID(uuidString: uid) != nil else { errorMessage = "The user ID must be a UUID."; return }
        do {
            let c = try makeClient(url, uid, nil)
            try await c.unlock(privateKey: privateKey, passphrase: passphrase)
            try await c.authenticate()
            try store.set(Data(privateKey.utf8), for: .privateKey)
            try store.set(Data(passphrase.utf8), for: .passphrase)
            preferences.serverURL = url.absoluteString
            preferences.userId = uid
            preferences.serverFingerprint = await c.serverFingerprint ?? ""
            client = c
            try await finishUnlock(c)
        } catch {
            await client?.lock(); client = nil
            errorMessage = message(for: error)
        }
    }

    // MARK: Lock / unlock

    public func unlock() async {
        guard state == .locked else { return }
        errorMessage = nil
        state = .unlocking
        do {
            try await authenticator.authenticate(reason: "Unlock your Passbolt vault")
            guard let url = URL(string: preferences.serverURL),
                  let key = try store.get(.privateKey).flatMap({ String(data: $0, encoding: .utf8) }),
                  let pass = try store.get(.passphrase).flatMap({ String(data: $0, encoding: .utf8) })
            else { throw PassboltError.notConfigured }
            let pinned = preferences.serverFingerprint.isEmpty ? nil : preferences.serverFingerprint
            let c = try makeClient(url, preferences.userId, pinned)
            try await c.unlock(privateKey: key, passphrase: pass)
            try await c.authenticate()
            client = c
            try await finishUnlock(c)
        } catch {
            await client?.lock(); client = nil
            state = .locked
            errorMessage = message(for: error)
        }
    }

    private func finishUnlock(_ c: PassboltClient) async throws {
        isLoading = true
        defer { isLoading = false }
        _ = try await c.loadResources()
        state = .unlocked
        touch()
        startInactivityTimer()
        refreshResults()
    }

    public func lock() async {
        inactivityTask?.cancel(); inactivityTask = nil
        clipboard.clearIfUnchanged()
        detail = nil; results = []; query = ""
        let c = client; client = nil
        await c?.lock()
        if state != .unconfigured { state = .locked }
    }

    // MARK: Inactivity

    public func touch() { lastActivity = Date() }

    /// Locks if idle longer than the configured timeout. Called by a timer; exposed for tests.
    public func checkInactivity(now: Date = Date()) async {
        let minutes = preferences.autoLockMinutes
        guard state == .unlocked, minutes > 0, now.timeIntervalSince(lastActivity) >= minutes * 60 else { return }
        await lock()
    }

    private func startInactivityTimer() {
        inactivityTask?.cancel()
        inactivityTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 10_000_000_000)
                await self?.checkInactivity()
            }
        }
    }

    // MARK: Search & detail

    private func refreshResults() {
        guard state == .unlocked, let client else { results = []; return }
        let q = query
        Task { [weak self] in
            let r = await client.searchResources(query: q)
            guard let self, self.query == q else { return }
            self.results = r
        }
    }

    public func select(_ resource: PassboltResource) async {
        touch(); errorMessage = nil
        guard let client else { return }
        do {
            detail = ResourceDetail(resource: resource, secret: try await client.getSecret(for: resource))
        } catch {
            errorMessage = message(for: error)
        }
    }

    /// Drops decrypted data from memory (called on back / popover close).
    public func clearDetail() { detail = nil; copiedField = nil }

    // MARK: Copy

    public func copy(_ field: String, value: String) {
        touch()
        clipboard.copy(value, clearAfter: preferences.clipboardTimeout)
        copiedField = field
        Task { [weak self] in
            try? await Task.sleep(nanoseconds: 1_500_000_000)
            if self?.copiedField == field { self?.copiedField = nil }
        }
    }

    public func totpCode() -> String? { detail?.secret.totp.flatMap { TOTP.code(for: $0) } }

    // MARK: Security settings

    public func clearCachedData() { detail = nil; results = []; query = "" }

    public func clearKeychainCredentials() async {
        await lock()
        try? store.deleteAll()
        preferences.resetAccount()
        state = .unconfigured
    }

    /// Called on quit: remove our secret from the clipboard if it is still there.
    public func prepareForTermination() { clipboard.clearIfUnchanged() }

    public func dismissError() { errorMessage = nil }

    private func message(for error: Error) -> String {
        (error as? PassboltError)?.localizedDescription ?? "Something went wrong."
    }
}
