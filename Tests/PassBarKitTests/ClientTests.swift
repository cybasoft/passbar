import XCTest
@testable import PassBarKit

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

    func testMFAAccountThrowsMFARequiredThenVerifies() async throws {
        let t = MockTransport.standard()
        t.routes["/users/me.json"] = (403, [:])
        let c = try makeClient(t)
        try await c.unlock(privateKey: "PRIV:user", passphrase: "x")
        do { try await c.authenticate(); XCTFail() } catch { XCTAssertEqual(error as? PassboltError, .mfaRequired) }
        t.routes["/mfa/verify/totp.json"] = (200, [:])
        try await c.verifyMFA(code: "123456")
        t.routes["/mfa/verify/totp.json"] = (400, [:])
        do { try await c.verifyMFA(code: "1"); XCTFail() } catch { XCTAssertEqual(error as? PassboltError, .mfaInvalidCode) }
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

    func testCreateV5EncryptsMetadataAndSecret() async throws {
        let t = MockTransport.standard()
        let c = try makeClient(t)
        try await c.unlock(privateKey: "PRIV:user", passphrase: "x")
        try await c.authenticate()
        _ = try await c.loadResources()
        let r = try await c.createResource(NewResource(name: "Site", uri: "https://s.example", username: "me",
                                                      password: "hunter2", totpSecret: "GEZDGNBVGY3TQOJQ", notes: "n"))
        XCTAssertEqual(r.id, "new-1")
        let post = try XCTUnwrap(t.requests.last { $0.httpMethod == "POST" && $0.url?.path == "/resources.json" })
        let body = try XCTUnwrap(JSONSerialization.jsonObject(with: post.httpBody!) as? [String: Any])
        XCTAssertEqual(body["resource_type_id"] as? String, "t3")
        XCTAssertEqual(body["metadata_key_id"] as? String, "mk1")
        XCTAssertEqual(body["metadata_key_type"] as? String, "shared_key")
        let meta = try XCTUnwrap(MockPGP.decode(body["metadata"] as! String))
        XCTAssertEqual(meta.owner, "shared")
        let metaJSON = try XCTUnwrap(JSONSerialization.jsonObject(with: meta.plain) as? [String: Any])
        XCTAssertEqual(metaJSON["name"] as? String, "Site")
        XCTAssertEqual(metaJSON["uris"] as? [String], ["https://s.example"])
        let secrets = try XCTUnwrap(body["secrets"] as? [[String: String]])
        XCTAssertEqual(secrets.first?["user_id"], "u1")
        let secret = try XCTUnwrap(MockPGP.decode(secrets[0]["data"]!))
        XCTAssertEqual(secret.owner, "user")
        let secretJSON = try XCTUnwrap(JSONSerialization.jsonObject(with: secret.plain) as? [String: Any])
        XCTAssertEqual(secretJSON["password"] as? String, "hunter2")
        XCTAssertNotNil(secretJSON["totp"])
        let all = await c.searchResources(query: "Site")
        XCTAssertEqual(all.first?.id, "new-1")
    }

    func testCreateUnsupportedWithoutKnownType() async throws {
        let t = MockTransport.standard()
        t.routes["/resource-types.json"] = (200, [["id": "t9", "slug": "totp"]])
        let c = try makeClient(t)
        try await c.unlock(privateKey: "PRIV:user", passphrase: "x")
        try await c.authenticate()
        _ = try await c.loadResources()
        do { _ = try await c.createResource(NewResource(name: "a", password: "b")); XCTFail() }
        catch { XCTAssertEqual(error as? PassboltError, .createUnsupported) }
    }

    private func loadedClient(_ t: MockTransport) async throws -> (PassboltAPIClient, PassboltResource) {
        let c = try makeClient(t)
        try await c.unlock(privateKey: "PRIV:user", passphrase: "x")
        try await c.authenticate()
        let all = try await c.loadResources()
        let aws = try XCTUnwrap(all.first { $0.id == "r1" })
        return (c, aws)
    }

    func testEditableDraftSeparatesNoteFromDescription() async throws {
        let (c, aws) = try await loadedClient(.standard())
        let d = try await c.editableDraft(for: aws)
        XCTAssertEqual(d.description, "old")
        XCTAssertEqual(d.notes, "secret note")
        XCTAssertEqual(d.password, "pw-1")
        XCTAssertEqual(d.totpSecret, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
    }

    func testUpdateReencryptsForEveryUserAndKeepsOtherMetadata() async throws {
        let t = MockTransport.standard()
        let (c, aws) = try await loadedClient(t)
        var d = try await c.editableDraft(for: aws)
        d.name = "AWS Prod"; d.password = "new-pw"; d.description = ""
        let updated = try await c.updateResource(aws, with: d)
        XCTAssertEqual(updated.name, "AWS Prod")
        let put = try XCTUnwrap(t.requests.last { $0.httpMethod == "PUT" && $0.url?.path == "/resources/r1.json" })
        let body = try XCTUnwrap(JSONSerialization.jsonObject(with: put.httpBody!) as? [String: Any])
        XCTAssertEqual(body["resource_type_id"] as? String, "t3")   // TOTP kept -> with-totp type
        let meta = try XCTUnwrap(MockPGP.decode(body["metadata"] as! String))
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: meta.plain) as? [String: Any])
        XCTAssertEqual(json["name"] as? String, "AWS Prod")
        XCTAssertEqual(json["icon"] as? String, "x")
        XCTAssertNil(json["description"])
        XCTAssertEqual(json["uris"] as? [String], ["https://aws.example.com", "https://b.example"])
        let secrets = try XCTUnwrap(body["secrets"] as? [[String: String]])
        XCTAssertEqual(secrets.map { $0["user_id"] }, ["u1", "u2"])
        XCTAssertEqual(MockPGP.decode(secrets[1]["data"]!)?.owner, "other")
        let secret = try XCTUnwrap(JSONSerialization.jsonObject(with: MockPGP.decode(secrets[0]["data"]!)!.plain) as? [String: Any])
        XCTAssertEqual(secret["password"] as? String, "new-pw")
        XCTAssertEqual(secret["description"] as? String, "secret note")
        XCTAssertEqual((secret["totp"] as? [String: Any])?["digits"] as? Int, 8)
        let found = await c.searchResources(query: "AWS Prod")
        XCTAssertEqual(found.count, 1)
    }

    func testUpdateRefusedWhenRecipientKeyMissing() async throws {
        let t = MockTransport.standard()
        t.routes["/users.json"] = (200, [["id": "u1", "gpgkey": ["armored_key": "PUB:user"]], ["id": "u2"]])
        let (c, aws) = try await loadedClient(t)
        do { _ = try await c.updateResource(aws, with: NewResource(name: "a", password: "b")); XCTFail() }
        catch { XCTAssertEqual(error as? PassboltError, .editUnsupported) }
        XCTAssertFalse(t.requests.contains { $0.httpMethod == "PUT" })
    }

    func testEditUnsupportedForPasswordStringType() async throws {
        let (c, _) = try await loadedClient(.standard())
        let found = await c.searchResources(query: "GitHub")
        let gh = try XCTUnwrap(found.first)
        do { _ = try await c.editableDraft(for: gh); XCTFail() }
        catch { XCTAssertEqual(error as? PassboltError, .editUnsupported) }
    }
}
