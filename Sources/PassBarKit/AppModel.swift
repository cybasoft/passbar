import Foundation
import Combine

public enum LockState: Equatable { case unconfigured, locked, unlocking, awaitingMFA, unlocked }

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
    /// Shows the new-credential form in place of the list.
    @Published public var isCreating = false
    /// In-progress new credential; survives the popover closing (e.g. copying from another app). Cleared on lock or save.
    @Published public var draft = NewResource()
    /// Resource being edited and its in-progress values; like `draft`, kept until saved, cancelled or locked.
    @Published public private(set) var editingResource: PassboltResource?
    @Published public var editDraft = NewResource()
    /// True only until the first unlock attempt: after any lock the user must unlock explicitly.
    public private(set) var shouldAutoPromptUnlock = true

    public let preferences: Preferences
    private let store: SecretStore
    private let authenticator: LocalAuthenticator
    private let clipboard: ClipboardManager
    private let makeClient: (URL, String, String?) throws -> PassboltClient
    private var client: PassboltClient?
    private var lastActivity = Date()
    private var inactivityTask: Task<Void, Never>?
    /// First-time setup waiting on an MFA code; secrets are only stored once it succeeds.
    private var pendingSetup: (url: URL, userId: String, privateKey: String, passphrase: String)?
    private static let mfaTimeoutNanoseconds: UInt64 = 120_000_000_000
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
            client = c
            pendingSetup = (url, uid, privateKey, passphrase)
            try await c.authenticate()
            try await completeSetup()
        } catch PassboltError.mfaRequired {
            beginMFA()
        } catch {
            pendingSetup = nil
            await client?.lock(); client = nil
            errorMessage = message(for: error)
        }
    }

    private func completeSetup() async throws {
        guard let c = client, let s = pendingSetup else { return }
        try store.set(Data(s.privateKey.utf8), for: .privateKey)
        try store.set(Data(s.passphrase.utf8), for: .passphrase)
        preferences.serverURL = s.url.absoluteString
        preferences.userId = s.userId
        preferences.serverFingerprint = await c.serverFingerprint ?? ""
        pendingSetup = nil
        try await finishUnlock(c)
    }

    // MARK: Lock / unlock

    public func unlock() async {
        shouldAutoPromptUnlock = false
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
            client = c
            try await c.authenticate()
            try await finishUnlock(c)
        } catch PassboltError.mfaRequired {
            beginMFA()
        } catch {
            await client?.lock(); client = nil
            state = .locked
            errorMessage = message(for: error)
        }
    }

    private func beginMFA() {
        state = .awaitingMFA
        // The unlocked key stays in memory while we wait, so don't wait forever.
        inactivityTask?.cancel()
        inactivityTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: Self.mfaTimeoutNanoseconds)
            guard !Task.isCancelled else { return }
            await self?.cancelMFA()
        }
    }

    /// Completes sign-in with an authenticator-app code. A wrong code leaves the prompt open.
    public func submitMFA(_ code: String) async {
        guard state == .awaitingMFA, let c = client else { return }
        errorMessage = nil
        do {
            try await c.verifyMFA(code: code.filter(\.isNumber))
            if pendingSetup != nil { try await completeSetup() } else { try await finishUnlock(c) }
        } catch PassboltError.mfaInvalidCode {
            errorMessage = message(for: PassboltError.mfaInvalidCode)
        } catch {
            await cancelMFA()
            errorMessage = message(for: error)
        }
    }

    public func cancelMFA() async {
        guard state == .awaitingMFA else { return }
        inactivityTask?.cancel(); inactivityTask = nil
        let wasSetup = pendingSetup != nil
        pendingSetup = nil
        await client?.lock(); client = nil
        state = wasSetup ? .unconfigured : .locked
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
        shouldAutoPromptUnlock = false
        inactivityTask?.cancel(); inactivityTask = nil
        pendingSetup = nil
        clipboard.clearIfUnchanged()
        detail = nil; results = []; query = ""; isCreating = false; draft = NewResource()
        cancelEdit()
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
        let recents = preferences.recentResourceIds
        Task { [weak self] in
            let r = await client.searchResources(query: q)
            guard let self, self.query == q else { return }
            self.results = Self.limited(r, query: q, recents: recents)
        }
    }

    /// Empty query: recently opened first, then the rest alphabetically. Always capped.
    static func limited(_ all: [PassboltResource], query: String, recents: [String]) -> [PassboltResource] {
        let limit = ResourceSearch.listLimit
        guard query.trimmingCharacters(in: .whitespaces).isEmpty else { return Array(all.prefix(limit)) }
        let byId = Dictionary(all.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        let recent = recents.compactMap { byId[$0] }
        let recentIds = Set(recent.map(\.id))
        return Array((recent + all.filter { !recentIds.contains($0.id) }).prefix(limit))
    }

    public func select(_ resource: PassboltResource) async {
        touch(); errorMessage = nil
        guard let client else { return }
        do {
            detail = ResourceDetail(resource: resource, secret: try await client.getSecret(for: resource))
            preferences.recordRecent(resource.id)
        } catch {
            await handleFailure(error)
        }
    }

    /// Creates a credential. Returns true on success.
    public func createResource(_ draft: NewResource) async -> Bool {
        touch(); errorMessage = nil
        guard let client else { return false }
        guard let d = validated(draft) else { return false }
        do {
            let r = try await client.createResource(d)
            preferences.recordRecent(r.id)
            isCreating = false
            self.draft = NewResource()
            refreshResults()
            return true
        } catch {
            await handleFailure(error)
            return false
        }
    }

    /// Trims and checks a form; sets `errorMessage` and returns nil if invalid.
    private func validated(_ draft: NewResource) -> NewResource? {
        var d = draft
        d.name = d.name.trimmingCharacters(in: .whitespacesAndNewlines)
        d.uri = d.uri.trimmingCharacters(in: .whitespacesAndNewlines)
        d.username = d.username.trimmingCharacters(in: .whitespacesAndNewlines)
        d.totpSecret = d.totpSecret.filter { !$0.isWhitespace }.uppercased()
        guard !d.name.isEmpty, !d.password.isEmpty else { errorMessage = "Name and password are required."; return nil }
        if !d.totpSecret.isEmpty, TOTP.code(for: TOTPParameters(secretKey: d.totpSecret)) == nil {
            errorMessage = "The TOTP key is not valid."; return nil
        }
        return d
    }

    /// Loads the resource's current values into the edit form.
    public func beginEdit(_ resource: PassboltResource) async {
        touch(); errorMessage = nil
        guard let client else { return }
        do {
            editDraft = try await client.editableDraft(for: resource)
            editingResource = resource
        } catch {
            await handleFailure(error)
        }
    }

    public func cancelEdit() { editingResource = nil; editDraft = NewResource() }

    /// Saves the edit form and shows the updated resource. Returns true on success.
    public func saveEdit() async -> Bool {
        touch(); errorMessage = nil
        guard let client, let resource = editingResource, let d = validated(editDraft) else { return false }
        do {
            let updated = try await client.updateResource(resource, with: d)
            cancelEdit()
            await select(updated)
            refreshResults()
            return true
        } catch {
            await handleFailure(error)
            return false
        }
    }

    /// Drops decrypted data from memory (called on back / popover close).
    public func clearDetail() { detail = nil; copiedField = nil; refreshResults() }

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

    public func clearCachedData() { detail = nil; results = []; query = ""; isCreating = false; draft = NewResource(); cancelEdit() }

    public func clearKeychainCredentials() async {
        await lock()
        try? store.deleteAll()
        preferences.resetAccount()
        state = .unconfigured
    }

    /// Called on quit: remove our secret from the clipboard if it is still there.
    public func prepareForTermination() { clipboard.clearIfUnchanged() }

    public func dismissError() { errorMessage = nil }

    /// An expired server session locks the app so the user re-authenticates instead of retrying.
    private func handleFailure(_ error: Error) async {
        if (error as? PassboltError) == .authenticationExpired { await lock() }
        errorMessage = message(for: error)
    }

    private func message(for error: Error) -> String {
        (error as? PassboltError)?.localizedDescription ?? "Something went wrong."
    }
}
