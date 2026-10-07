import Foundation
@testable import PassBarKit

/// Fake PGP: "encryption" is base64 tagged with the recipient. Test-only, not secure.
final class MockPGP: PGPProvider, @unchecked Sendable {
    func openKey(armored: String, passphrase: String) throws -> PGPKeyHandle {
        guard armored.hasPrefix("PRIV:") else { throw PassboltError.invalidKey }
        guard passphrase != "bad" else { throw PassboltError.wrongPassphrase }
        return MockKey(owner: String(armored.dropFirst(5)))
    }
    static func encrypt(_ s: String, to owner: String) -> String { "ENC:\(owner):" + Data(s.utf8).base64EncodedString() }
    static func decode(_ armored: String) -> (owner: String, plain: Data)? {
        let parts = armored.split(separator: ":", maxSplits: 2).map(String.init)
        guard parts.count == 3, parts[0] == "ENC", let d = Data(base64Encoded: parts[2]) else { return nil }
        return (parts[1], d)
    }
}

final class MockKey: PGPKeyHandle, @unchecked Sendable {
    let owner: String
    private(set) var closed = false
    init(owner: String) { self.owner = owner }
    var fingerprint: String { "FP-\(owner)" }
    func decrypt(_ m: String, verifyingWith: String?) throws -> Data {
        guard let (o, p) = MockPGP.decode(m), o == owner else { throw PassboltError.decryptionFailed }
        return p
    }
    func signAndEncrypt(_ message: Data, to publicKey: String) throws -> String {
        MockPGP.encrypt(String(data: message, encoding: .utf8)!, to: String(publicKey.dropFirst(4)))
    }
    func close() { closed = true }
}

/// Canned Passbolt server.
final class MockTransport: HTTPTransport, @unchecked Sendable {
    var routes: [String: (Int, Any)] = [:]
    var requests: [URLRequest] = []
    var error: Error?
    var loginStatus = 200

    func send(_ request: URLRequest) async throws -> (data: Data, status: Int) {
        requests.append(request)
        if let error { throw error }
        let path = request.url!.path
        if path == "/auth/jwt/login.json" {
            guard loginStatus == 200 else { return (Data(), loginStatus) }
            let body = try JSONSerialization.jsonObject(with: request.httpBody!) as! [String: String]
            let (_, plain) = MockPGP.decode(body["challenge"]!)!
            var challenge = try JSONSerialization.jsonObject(with: plain) as! [String: Any]
            challenge["access_token"] = "access-token-test"
            challenge["refresh_token"] = "refresh-token-test"
            let reply = String(data: try JSONSerialization.data(withJSONObject: challenge), encoding: .utf8)!
            return try wrap(["challenge": MockPGP.encrypt(reply, to: "user")])
        }
        guard let (status, body) = routes[path] else { return (Data(), 404) }
        return status == 200 ? try wrap(body) : (Data(), status)
    }

    private func wrap(_ body: Any) throws -> (Data, Int) {
        (try JSONSerialization.data(withJSONObject: ["header": ["code": 200], "body": body]), 200)
    }

    static func standard() -> MockTransport {
        let t = MockTransport()
        t.routes["/auth/verify.json"] = (200, ["fingerprint": "AABB", "keydata": "PUB:server"])
        t.routes["/resource-types.json"] = (200, [["id": "t1", "slug": "v5-default"], ["id": "t2", "slug": "v5-password-string"]])
        t.routes["/metadata/keys.json"] = (200, [[
            "id": "mk1",
            "metadata_private_keys": [["data": MockPGP.encrypt(#"{"armored_key":"PRIV:shared","passphrase":""}"#, to: "user")]],
        ]])
        t.routes["/resources.json"] = (200, [
            ["id": "r1", "resource_type_id": "t1", "metadata_key_id": "mk1", "metadata_key_type": "shared_key",
             "metadata": MockPGP.encrypt(#"{"name":"AWS Production","username":"admin@example.com","uris":["https://aws.example.com"]}"#, to: "shared")],
            ["id": "r2", "resource_type_id": "t2", "metadata_key_type": "user_key",
             "metadata": MockPGP.encrypt(#"{"name":"GitHub","username":"octo","uri":"https://github.com"}"#, to: "user")],
            ["id": "r3", "name": "Legacy v4", "username": "old", "uri": "http://old.example"],
        ])
        t.routes["/secrets/resource/r1.json"] = (200, ["data": MockPGP.encrypt(
            #"{"password":"pw-1","totp":{"secret_key":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","digits":8}}"#, to: "user")])
        t.routes["/secrets/resource/r2.json"] = (200, ["data": MockPGP.encrypt("{plain-password", to: "user")])
        return t
    }
}

func makeClient(_ transport: MockTransport, pinned: String? = nil) throws -> PassboltAPIClient {
    try PassboltAPIClient(serverURL: URL(string: "https://passbolt.example")!, userId: "u1",
                          pinnedFingerprint: pinned, transport: transport, pgp: MockPGP())
}
