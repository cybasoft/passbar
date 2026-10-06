import XCTest
@testable import PassboltKit

final class SearchTests: XCTestCase {
    let items = [
        PassboltResource(id: "1", name: "AWS Production", username: "admin@example.com", uri: "https://aws.example.com"),
        PassboltResource(id: "2", name: "GitHub", username: "octo", uri: "https://github.com"),
        PassboltResource(id: "3", name: "Cloudflare", username: "ops@github.io"),
    ]
    func testEmptyQueryReturnsAllSorted() { XCTAssertEqual(ResourceSearch.filter(items, query: "").map(\.id), ["1", "3", "2"]) }
    func testNameBeatsUsername() { XCTAssertEqual(ResourceSearch.filter(items, query: "git").map(\.id), ["2", "3"]) }
    func testCaseInsensitiveUsernameAndURL() {
        XCTAssertEqual(ResourceSearch.filter(items, query: "ADMIN").map(\.id), ["1"])
        XCTAssertEqual(ResourceSearch.filter(items, query: "aws.example").map(\.id), ["1"])
    }
    func testNoMatch() { XCTAssertTrue(ResourceSearch.filter(items, query: "zzz").isEmpty) }
}

final class TOTPTests: XCTestCase {
    // RFC 6238 appendix B test vectors (SHA1, secret "12345678901234567890").
    func testRFC6238() {
        let p = TOTPParameters(secretKey: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", digits: 8)
        XCTAssertEqual(TOTP.code(for: p, at: Date(timeIntervalSince1970: 59)), "94287082")
        XCTAssertEqual(TOTP.code(for: p, at: Date(timeIntervalSince1970: 1111111109)), "07081804")
    }
    func testInvalidSecret() { XCTAssertNil(TOTP.code(for: TOTPParameters(secretKey: "!!!"))) }
}

final class SecretStoreTests: XCTestCase {
    func testInMemoryRoundTripAndDelete() throws {
        let s = InMemorySecretStore()
        try s.set(Data("a".utf8), for: .privateKey)
        XCTAssertEqual(try s.get(.privateKey), Data("a".utf8))
        try s.deleteAll()
        XCTAssertNil(try s.get(.privateKey))
    }
    func testKeychainRoundTrip() throws {
        let s = KeychainSecretStore(service: "test.passbar.\(UUID().uuidString)")
        defer { try? s.deleteAll() }
        do { try s.set(Data("dummy".utf8), for: .passphrase) }
        catch { throw XCTSkip("Keychain unavailable in this environment") }
        try s.set(Data("dummy2".utf8), for: .passphrase)   // update path
        XCTAssertEqual(try s.get(.passphrase), Data("dummy2".utf8))
        try s.deleteAll()
        XCTAssertNil(try s.get(.passphrase))
    }
}

final class FakePasteboard: PasteboardProtocol {
    var value: String?
    func string() -> String? { value }
    func write(_ string: String) { value = string }
    func clear() { value = nil }
}

@MainActor
final class ClipboardTests: XCTestCase {
    func testClearsOwnContent() async {
        let pb = FakePasteboard()
        let cm = ClipboardManager(pasteboard: pb, sleep: { _ in })
        cm.copy("secret", clearAfter: 30)
        XCTAssertEqual(pb.value, "secret")
        try? await Task.sleep(nanoseconds: 100_000_000)
        XCTAssertNil(pb.value)
    }
    func testDoesNotClearForeignContent() async {
        let pb = FakePasteboard()
        let cm = ClipboardManager(pasteboard: pb, sleep: { _ in try await Task.sleep(nanoseconds: 50_000_000) })
        cm.copy("secret", clearAfter: 30)
        pb.value = "copied by another app"
        try? await Task.sleep(nanoseconds: 200_000_000)
        XCTAssertEqual(pb.value, "copied by another app")
    }
    func testZeroTimeoutNeverClears() async {
        let pb = FakePasteboard()
        let cm = ClipboardManager(pasteboard: pb, sleep: { _ in })
        cm.copy("secret", clearAfter: 0)
        try? await Task.sleep(nanoseconds: 100_000_000)
        XCTAssertEqual(pb.value, "secret")
    }
}

struct AllowAuth: LocalAuthenticator { func authenticate(reason: String) async throws {} }
struct DenyAuth: LocalAuthenticator { func authenticate(reason: String) async throws { throw PassboltError.biometricsFailed } }

@MainActor
final class AppModelTests: XCTestCase {
    func makeModel(auth: LocalAuthenticator = AllowAuth(), store: InMemorySecretStore = InMemorySecretStore(),
                   transport: MockTransport = .standard(), pb: FakePasteboard = FakePasteboard()) -> AppModel {
        let defaults = UserDefaults(suiteName: "test.\(UUID().uuidString)")!
        let model = AppModel(preferences: Preferences(defaults: defaults), store: store, authenticator: auth,
                             clipboard: ClipboardManager(pasteboard: pb, sleep: { _ in }),
                             makeClient: { url, uid, fp in
                                 try PassboltAPIClient(serverURL: url, userId: uid, pinnedFingerprint: fp,
                                                       transport: transport, pgp: MockPGP())
                             })
        return model
    }
    let uid = "8bb80df5-700c-48ce-b568-85a60fc3c8f2"

    func testStartsUnconfigured() { XCTAssertEqual(makeModel().state, .unconfigured) }

    func testConfigureRejectsHTTP() async {
        let m = makeModel()
        await m.configure(serverURL: "http://x.example", userId: uid, privateKey: "PRIV:user", passphrase: "p")
        XCTAssertEqual(m.state, .unconfigured)
        XCTAssertEqual(m.errorMessage, PassboltError.insecureServerURL.localizedDescription)
    }

    func testFailedConfigureStoresNothing() async {
        let store = InMemorySecretStore()
        let m = makeModel(store: store)
        await m.configure(serverURL: "https://passbolt.example", userId: uid, privateKey: "PRIV:user", passphrase: "bad")
        XCTAssertNil(try store.get(.privateKey))
        XCTAssertEqual(m.state, .unconfigured)
    }

    func testConfigureThenLockUnlockFlow() async throws {
        let store = InMemorySecretStore()
        let m = makeModel(store: store)
        await m.configure(serverURL: "https://passbolt.example", userId: uid, privateKey: "PRIV:user", passphrase: "p")
        XCTAssertEqual(m.state, .unlocked)
        XCTAssertNotNil(try store.get(.privateKey))
        XCTAssertFalse(m.preferences.serverFingerprint.isEmpty)
        try await Task.sleep(nanoseconds: 50_000_000)
        XCTAssertEqual(m.results.count, 3)

        await m.lock()
        XCTAssertEqual(m.state, .locked)
        XCTAssertTrue(m.results.isEmpty)
        XCTAssertNil(m.detail)

        await m.unlock()
        XCTAssertEqual(m.state, .unlocked)
    }

    func testUnlockDeniedStaysLocked() async {
        let store = InMemorySecretStore()
        let m1 = makeModel(store: store)
        await m1.configure(serverURL: "https://passbolt.example", userId: uid, privateKey: "PRIV:user", passphrase: "p")
        let m2 = AppModel(preferences: m1.preferences, store: store, authenticator: DenyAuth(),
                          clipboard: ClipboardManager(pasteboard: FakePasteboard()), makeClient: { _, _, _ in fatalError() })
        XCTAssertEqual(m2.state, .locked)
        await m2.unlock()
        XCTAssertEqual(m2.state, .locked)
        XCTAssertEqual(m2.errorMessage, PassboltError.biometricsFailed.localizedDescription)
    }

    func testAutoLockAfterInactivity() async {
        let m = makeModel()
        await m.configure(serverURL: "https://passbolt.example", userId: uid, privateKey: "PRIV:user", passphrase: "p")
        m.preferences.autoLockMinutes = 5
        await m.checkInactivity(now: Date().addingTimeInterval(60))
        XCTAssertEqual(m.state, .unlocked)
        await m.checkInactivity(now: Date().addingTimeInterval(301))
        XCTAssertEqual(m.state, .locked)
    }

    func testAutoLockDisabled() async {
        let m = makeModel()
        await m.configure(serverURL: "https://passbolt.example", userId: uid, privateKey: "PRIV:user", passphrase: "p")
        m.preferences.autoLockMinutes = 0
        await m.checkInactivity(now: Date().addingTimeInterval(99999))
        XCTAssertEqual(m.state, .unlocked)
    }

    func testLockClearsClipboardAndDetail() async throws {
        let pb = FakePasteboard()
        let m = makeModel(pb: pb)
        await m.configure(serverURL: "https://passbolt.example", userId: uid, privateKey: "PRIV:user", passphrase: "p")
        try await Task.sleep(nanoseconds: 50_000_000)
        await m.select(m.results[0])
        XCTAssertNotNil(m.detail)
        m.copy("password", value: "pw-1")
        XCTAssertEqual(pb.value, "pw-1")
        await m.lock()
        XCTAssertNil(pb.value)
        XCTAssertNil(m.detail)
    }

    func testClearKeychainResetsEverything() async {
        let store = InMemorySecretStore()
        let m = makeModel(store: store)
        await m.configure(serverURL: "https://passbolt.example", userId: uid, privateKey: "PRIV:user", passphrase: "p")
        await m.clearKeychainCredentials()
        XCTAssertEqual(m.state, .unconfigured)
        XCTAssertNil(try store.get(.privateKey))
        XCTAssertNil(try store.get(.passphrase))
    }
}

/// Exercises the real Go/GopenPGP bridge with a throwaway key.
final class RealPGPTests: XCTestCase {
    func testRoundTripWithRealBridge() throws {
        let p = GopenPGPProvider()
        let key = try p.openKey(armored: TestKeys.privateKey, passphrase: TestKeys.passphrase)
        defer { key.close() }
        let enc = try key.signAndEncrypt(Data("hello".utf8), to: TestKeys.publicKey)
        XCTAssertTrue(enc.contains("BEGIN PGP MESSAGE"))
        XCTAssertEqual(try key.decrypt(enc, verifyingWith: TestKeys.publicKey), Data("hello".utf8))
    }
    func testWrongPassphraseAndGarbageKey() {
        let p = GopenPGPProvider()
        XCTAssertThrowsError(try p.openKey(armored: TestKeys.privateKey, passphrase: "nope")) {
            XCTAssertEqual($0 as? PassboltError, .wrongPassphrase)
        }
        XCTAssertThrowsError(try p.openKey(armored: "garbage", passphrase: "")) {
            XCTAssertEqual($0 as? PassboltError, .invalidKey)
        }
    }
}
