import XCTest
@testable import PassboltKit

final class ClientTests: XCTestCase {
    func testRejectsHTTP() {
        XCTAssertThrowsError(try PassboltAPIClient(serverURL: URL(string: "http://x.example")!, userId: "u",
                                                   transport: MockTransport(), pgp: MockPGP())) {
            XCTAssertEqual($0 as? PassboltError, .insecureServerURL)
        }
    }

    func testAuthenticateSuccessSetsFingerprintAndSendsBearer() async throws {
        let t = MockTransport.standard()
        let c = try makeClient(t)
        try await c.unlock(privateKey: "PRIV:user", passphrase: "x")
        try await c.authenticate()
        let fp = await c.serverFingerprint
        XCTAssertEqual(fp, "AABB")
        _ = try await c.loadResources()
        let authed = t.requests.last { $0.url?.path == "/resources.json" }
        XCTAssertEqual(authed?.value(forHTTPHeaderField: "Authorization"), "Bearer access-token-test")
    }

    func testAuthenticateRequiresUnlockedKey() async throws {
        let c = try makeClient(.standard())
        do { try await c.authenticate(); XCTFail() } catch { XCTAssertEqual(error as? PassboltError, .notConfigured) }
    }

    func testPinnedFingerprintMismatchRejected() async throws {
        let c = try makeClient(.standard(), pinned: "FFFF")
        try await c.unlock(privateKey: "PRIV:user", passphrase: "x")
        do { try await c.authenticate(); XCTFail() } catch { XCTAssertEqual(error as? PassboltError, .authenticationFailed) }
    }

    func testLoginRejectedMapsToAuthFailed() async throws {
        let t = MockTransport.standard(); t.loginStatus = 404
        let c = try makeClient(t)
        try await c.unlock(privateKey: "PRIV:user", passphrase: "x")
        do { try await c.authenticate(); XCTFail() } catch { XCTAssertEqual(error as? PassboltError, .authenticationFailed) }
    }

    func testWrongPassphrase() async throws {
        let c = try makeClient(.standard())
        do { try await c.unlock(privateKey: "PRIV:user", passphrase: "bad"); XCTFail() }
        catch { XCTAssertEqual(error as? PassboltError, .wrongPassphrase) }
    }

    func testTransportErrorsSurfaceWithoutDetails() async throws {
        let t = MockTransport.standard(); t.error = PassboltError.certificateInvalid
        let c = try makeClient(t)
        try await c.unlock(privateKey: "PRIV:user", passphrase: "x")
        do { try await c.authenticate(); XCTFail() } catch { XCTAssertEqual(error as? PassboltError, .certificateInvalid) }
    }

    func testExpiredTokenMapsToAuthExpired() async throws {
        let t = MockTransport.standard()
        let c = try makeClient(t)
        try await c.unlock(privateKey: "PRIV:user", passphrase: "x")
        try await c.authenticate()
        t.routes["/resources.json"] = (401, [:])
        do { _ = try await c.loadResources(); XCTFail() } catch { XCTAssertEqual(error as? PassboltError, .authenticationExpired) }
    }

    func testResourceParsingV5AndV4() async throws {
        let c = try makeClient(.standard())
        try await c.unlock(privateKey: "PRIV:user", passphrase: "x")
        try await c.authenticate()
        let rs = try await c.loadResources().sorted { $0.id < $1.id }
        XCTAssertEqual(rs.map(\.name), ["AWS Production", "GitHub", "Legacy v4"])
        XCTAssertEqual(rs[0].username, "admin@example.com")
        XCTAssertEqual(rs[0].uri, "https://aws.example.com")
        XCTAssertEqual(rs[2].uri, "http://old.example")
    }

    func testSecretParsing() async throws {
        let c = try makeClient(.standard())
        try await c.unlock(privateKey: "PRIV:user", passphrase: "x")
        try await c.authenticate()
        let rs = try await c.loadResources()
        let aws = try XCTUnwrap(rs.first { $0.id == "r1" })
        let s = try await c.getSecret(for: aws)
        XCTAssertEqual(s.password, "pw-1")
        XCTAssertEqual(s.totp?.digits, 8)
        // "v5-password-string" type: the secret is the raw password even if it looks like JSON.
        let gh = try XCTUnwrap(rs.first { $0.id == "r2" })
        let s2 = try await c.getSecret(for: gh)
        XCTAssertEqual(s2.password, "{plain-password")
    }

    func testLockWipesState() async throws {
        let t = MockTransport.standard()
        let c = try makeClient(t)
        try await c.unlock(privateKey: "PRIV:user", passphrase: "x")
        try await c.authenticate()
        _ = try await c.loadResources()
        let before = await c.searchResources(query: "")
        XCTAssertEqual(before.count, 3)
        await c.lock()
        let after = await c.searchResources(query: "")
        XCTAssertTrue(after.isEmpty)
        XCTAssertTrue(t.requests.contains { $0.url?.path == "/auth/jwt/logout.json" })
        do { _ = try await c.loadResources(); XCTFail() } catch { XCTAssertEqual(error as? PassboltError, .notConfigured) }
    }
}
