import Foundation

public protocol PassboltClient: Sendable {
    /// Opens the user's private key in memory (needed for every operation).
    func unlock(privateKey: String, passphrase: String) async throws
    /// Passbolt GpgJwtAuth login. Tokens are kept in memory only.
    func authenticate() async throws
    /// Fetches resources and decrypts their metadata into an in-memory index.
    func loadResources() async throws -> [PassboltResource]
    func searchResources(query: String) async -> [PassboltResource]
    func getSecret(for resource: PassboltResource) async throws -> ResourceSecret
    /// Encrypts and stores a new credential; the result is added to the in-memory index.
    func createResource(_ draft: NewResource) async throws -> PassboltResource
    /// Current values of a resource, decrypted, to pre-fill the edit form.
    func editableDraft(for resource: PassboltResource) async throws -> NewResource
    /// Re-encrypts the resource with the edited values for everyone who has access.
    func updateResource(_ resource: PassboltResource, with draft: NewResource) async throws -> PassboltResource
    /// Wipes keys, tokens and the metadata index; best-effort server logout.
    func lock() async
    var serverFingerprint: String? { get async }
}

/// Talks to the documented Passbolt REST API (see open-api-specs.yaml):
///  GET  /auth/verify.json            server public key
///  POST /auth/jwt/login.json         GpgJwtAuth login
///  POST /auth/jwt/logout.json
///  GET  /resource-types.json
///  GET  /metadata/keys.json          shared metadata keys (v5)
///  GET  /resources.json
///  POST /resources.json
///  GET/PUT /resources/{id}.json
///  GET  /users/me.json
///  GET  /secrets/resource/{id}.json
///
/// SECURITY CRITICAL: handles tokens, the unlocked private key and decrypted
/// secrets. Nothing here logs, persists or forwards them anywhere but Passbolt.
public actor PassboltAPIClient: PassboltClient {
    private let baseURL: URL
    private let userId: String
    private let transport: HTTPTransport
    private let pgp: PGPProvider
    private let pinnedFingerprint: String?

    private var userKey: PGPKeyHandle?
    private var metadataKeys: [String: PGPKeyHandle] = [:]
    /// Newest usable shared metadata key (public half), used to encrypt new v5 metadata.
    private var sharedMetadataKey: (id: String, armored: String)?
    private var accessToken: String?
    private var refreshToken: String?
    private var typeSlugs: [String: String] = [:]
    private var index: [PassboltResource] = []
    public private(set) var verifiedServerFingerprint: String?

    public var serverFingerprint: String? { verifiedServerFingerprint }

    /// - Parameter pinnedFingerprint: server key fingerprint trusted at first use; a
    ///   different key on later logins is rejected.
    public init(serverURL: URL, userId: String, pinnedFingerprint: String? = nil,
                transport: HTTPTransport, pgp: PGPProvider) throws {
        guard serverURL.scheme == "https", serverURL.host != nil else { throw PassboltError.insecureServerURL }
        self.baseURL = serverURL
        self.userId = userId
        self.pinnedFingerprint = pinnedFingerprint
        self.transport = transport
        self.pgp = pgp
    }

    // MARK: Key / session

    public func unlock(privateKey: String, passphrase: String) async throws {
        userKey?.close()
        userKey = try pgp.openKey(armored: privateKey, passphrase: passphrase)
    }

    public func lock() async {
        let refresh = refreshToken
        let access = accessToken
        userKey?.close(); userKey = nil
        metadataKeys.values.forEach { $0.close() }; metadataKeys = [:]; sharedMetadataKey = nil
        accessToken = nil; refreshToken = nil
        index = []; typeSlugs = [:]
        if let refresh, let access {   // best effort, errors ignored
            _ = try? await send("POST", "/auth/jwt/logout.json", body: ["refresh_token": refresh], token: access)
        }
    }

    // MARK: Authentication

    private struct VerifyBody: Decodable { let fingerprint: String; let keydata: String }
    private struct LoginBody: Decodable { let challenge: String }
    private struct LoginChallenge: Codable {
        var version: String
        var domain: String
        var verify_token: String
        var verify_token_expiry: Int?
        var access_token: String?
        var refresh_token: String?
    }

    public func authenticate() async throws {
        guard let key = userKey else { throw PassboltError.notConfigured }
        accessToken = nil; refreshToken = nil

        let verify: VerifyBody = try await get("/auth/verify.json", token: nil, failure: .authenticationFailed)
        let serverFP = verify.fingerprint.uppercased()
        if let pinned = pinnedFingerprint, pinned.uppercased() != serverFP { throw PassboltError.authenticationFailed }

        let token = UUID().uuidString.lowercased()
        let domain = baseURL.absoluteString.hasSuffix("/") ? String(baseURL.absoluteString.dropLast()) : baseURL.absoluteString
        let challenge = LoginChallenge(version: "1.0.0", domain: domain, verify_token: token,
                                       verify_token_expiry: Int(Date().timeIntervalSince1970) + 3600)
        let encrypted = try key.signAndEncrypt(try JSONEncoder().encode(challenge), to: verify.keydata)

        let (data, status) = try await send("POST", "/auth/jwt/login.json",
                                            body: ["user_id": userId, "challenge": encrypted], token: nil)
        guard status == 200 else { throw status == 400 || status == 401 || status == 404 ? PassboltError.authenticationFailed : PassboltError.serverError(status) }
        let login = try decodeBody(LoginBody.self, from: data)
        // The reply must be signed by the pinned/verified server key and echo our token.
        let plain: Data
        do { plain = try key.decrypt(login.challenge, verifyingWith: verify.keydata) }
        catch { throw PassboltError.authenticationFailed }
        guard let reply = try? JSONDecoder().decode(LoginChallenge.self, from: plain),
              reply.verify_token == token, let access = reply.access_token else {
            throw PassboltError.authenticationFailed
        }
        accessToken = access
        refreshToken = reply.refresh_token
        verifiedServerFingerprint = serverFP
    }

    // MARK: Resources

    private struct ResourceType: Decodable { let id: String; let slug: String }
    private struct MetadataKeyDTO: Decodable {
        let id: String
        let armored_key: String?
        let expired: String?
        let deleted: String?
        let metadata_private_keys: [PrivateKeyDTO]?

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            id = try c.decode(String.self, forKey: .id)
            metadata_private_keys = try c.decodeIfPresent([PrivateKeyDTO].self, forKey: .metadata_private_keys)
            // Tolerate unexpected shapes so an odd value never hides the key itself.
            armored_key = try? c.decodeIfPresent(String.self, forKey: .armored_key)
            expired = try? c.decodeIfPresent(String.self, forKey: .expired)
            deleted = try? c.decodeIfPresent(String.self, forKey: .deleted)
        }
        private enum CodingKeys: String, CodingKey { case id, armored_key, expired, deleted, metadata_private_keys }
    }
    private struct PrivateKeyDTO: Decodable { let data: String? }
    private struct MetadataPrivateKey: Decodable { let armored_key: String; let passphrase: String? }
    private struct ResourceDTO: Decodable {
        let id: String
        let resource_type_id: String?
        let metadata: String?
        let metadata_key_id: String?
        let metadata_key_type: String?
        let name: String?
        let username: String?
        let uri: String?
    }
    private struct MetadataJSON: Decodable {
        let name: String?
        let username: String?
        let uri: String?
        let uris: [String]?
    }

    public func loadResources() async throws -> [PassboltResource] {
        guard let key = userKey else { throw PassboltError.notConfigured }
        if let types: [ResourceType] = try? await get("/resource-types.json", failure: .invalidResponse) {
            typeSlugs = Dictionary(types.map { ($0.id, $0.slug) }, uniquingKeysWith: { a, _ in a })
        }
        try await loadMetadataKeys(userKey: key)
        let dtos: [ResourceDTO] = try await get("/resources.json", failure: .invalidResponse)

        let keys = metadataKeys
        let resources = await withTaskGroup(of: PassboltResource?.self) { group -> [PassboltResource] in
            for dto in dtos {
                group.addTask {
                    Self.resource(from: dto, userKey: key, metadataKeys: keys)
                }
            }
            var out: [PassboltResource] = []
            for await r in group { if let r { out.append(r) } }
            return out
        }
        index = resources
        return resources
    }

    private func loadMetadataKeys(userKey: PGPKeyHandle) async throws {
        metadataKeys.values.forEach { $0.close() }; metadataKeys = [:]; sharedMetadataKey = nil
        // v4-only servers may not offer this; treat failure as "no shared keys".
        guard let dtos: [MetadataKeyDTO] = try? await get("/metadata/keys.json?contain[metadata_private_keys]=1",
                                                          failure: .invalidResponse) else { return }
        for dto in dtos {
            guard let armored = dto.metadata_private_keys?.compactMap({ $0.data }).first,
                  let plain = try? userKey.decrypt(armored, verifyingWith: nil),
                  let pk = try? JSONDecoder().decode(MetadataPrivateKey.self, from: plain),
                  let handle = try? pgp.openKey(armored: pk.armored_key, passphrase: pk.passphrase ?? "")
            else { continue }
            metadataKeys[dto.id] = handle
            if sharedMetadataKey == nil, dto.deleted == nil, dto.expired == nil, let pub = dto.armored_key {
                sharedMetadataKey = (dto.id, pub)
            }
        }
    }

    private static func resource(from dto: ResourceDTO, userKey: PGPKeyHandle,
                                 metadataKeys: [String: PGPKeyHandle]) -> PassboltResource? {
        guard let armored = dto.metadata else {   // v4: plaintext metadata
            return PassboltResource(id: dto.id, name: dto.name ?? "(unnamed)", username: dto.username ?? "",
                                    uri: dto.uri ?? "", resourceTypeId: dto.resource_type_id)
        }
        let decryptor: PGPKeyHandle? = dto.metadata_key_type == "user_key" ? userKey
            : dto.metadata_key_id.flatMap { metadataKeys[$0] }
        guard let decryptor, let plain = try? decryptor.decrypt(armored, verifyingWith: nil),
              let meta = try? JSONDecoder().decode(MetadataJSON.self, from: plain) else {
            return PassboltResource(id: dto.id, name: "(unable to decrypt)", resourceTypeId: dto.resource_type_id)
        }
        return PassboltResource(id: dto.id, name: meta.name ?? "(unnamed)", username: meta.username ?? "",
                                uri: meta.uri ?? meta.uris?.first ?? "", resourceTypeId: dto.resource_type_id)
    }

    public func searchResources(query: String) -> [PassboltResource] {
        ResourceSearch.filter(index, query: query)
    }

    // MARK: Secrets

    private struct SecretDTO: Decodable { let data: String }
    private struct SecretJSON: Decodable {
        let password: String?
        let description: String?
        let totp: TOTPJSON?
    }
    private struct TOTPJSON: Decodable {
        let secret_key: String
        let algorithm: String?
        let digits: Int?
        let period: Int?
    }

    /// SECURITY CRITICAL: returns decrypted credential material to the caller.
    public func getSecret(for resource: PassboltResource) async throws -> ResourceSecret {
        guard let key = userKey else { throw PassboltError.notConfigured }
        let dto: SecretDTO = try await get("/secrets/resource/\(resource.id).json", failure: .notFound)
        guard let plain = try? key.decrypt(dto.data, verifyingWith: nil),
              let text = String(data: plain, encoding: .utf8) else { throw PassboltError.decryptionFailed }
        return Self.parseSecret(text, typeSlug: resource.resourceTypeId.flatMap { typeSlugs[$0] })
    }

    static func parseSecret(_ text: String, typeSlug: String?) -> ResourceSecret {
        let plainTypes = ["password-string", "v5-password-string"]
        if let slug = typeSlug, plainTypes.contains(slug) { return ResourceSecret(password: text) }
        if text.hasPrefix("{"), let json = try? JSONDecoder().decode(SecretJSON.self, from: Data(text.utf8)) {
            let totp = json.totp.map {
                TOTPParameters(secretKey: $0.secret_key, algorithm: $0.algorithm ?? "SHA1",
                               digits: $0.digits ?? 6, period: $0.period ?? 30)
            }
            return ResourceSecret(password: json.password, totp: totp, description: json.description)
        }
        return ResourceSecret(password: text)
    }

    // MARK: Create

    private struct MeDTO: Decodable { let gpgkey: GpgKeyDTO? }
    private struct GpgKeyDTO: Decodable { let armored_key: String }
    private struct CreatedDTO: Decodable { let id: String }

    /// SECURITY CRITICAL: encrypts new credential material for the server. Prefers the v5 format
    /// (metadata encrypted with the shared metadata key) and falls back to the v4 types.
    public func createResource(_ draft: NewResource) async throws -> PassboltResource {
        guard let key = userKey else { throw PassboltError.notConfigured }
        let totp: [String: Any]? = draft.totpSecret.isEmpty ? nil
            : ["secret_key": draft.totpSecret, "algorithm": "SHA1", "digits": 6, "period": 30]
        func typeId(_ slug: String) -> String? { typeSlugs.first { $0.value == slug }?.key }

        let me: MeDTO = try await get("/users/me.json?contain[gpgkey]=1", failure: .invalidResponse)
        guard let ownKey = me.gpgkey?.armored_key else { throw PassboltError.invalidResponse }

        var secret: [String: Any] = ["password": draft.password]
        var body: [String: Any] = ["expired": NSNull(), "folder_parent_id": NSNull()]
        let typeIdUsed: String

        if let shared = sharedMetadataKey, let tid = typeId(totp == nil ? "v5-default" : "v5-default-with-totp") {
            typeIdUsed = tid
            secret["object_type"] = "PASSBOLT_SECRET_DATA"
            var metadata: [String: Any] = ["object_type": "PASSBOLT_RESOURCE_METADATA", "resource_type_id": tid,
                                           "name": draft.name, "username": draft.username,
                                           "uris": draft.uri.isEmpty ? [] : [draft.uri]]
            if !draft.notes.isEmpty { metadata["description"] = draft.notes }
            body["metadata"] = try key.signAndEncrypt(try JSONSerialization.data(withJSONObject: metadata), to: shared.armored)
            body["metadata_key_id"] = shared.id
            body["metadata_key_type"] = "shared_key"
        } else if let tid = typeId(totp == nil ? "password-and-description" : "password-description-totp") {
            typeIdUsed = tid
            secret["description"] = draft.notes
            body["name"] = draft.name; body["username"] = draft.username; body["uri"] = draft.uri
        } else {
            throw PassboltError.createUnsupported
        }
        if let totp { secret["totp"] = totp }
        body["resource_type_id"] = typeIdUsed
        let encryptedSecret = try key.signAndEncrypt(try JSONSerialization.data(withJSONObject: secret), to: ownKey)
        body["secrets"] = [["user_id": userId, "data": encryptedSecret]]

        let (data, status) = try await send("POST", "/resources.json", body: body, token: accessToken)
        switch status {
        case 200, 201: break
        case 401: throw PassboltError.authenticationExpired
        case 400: throw PassboltError.invalidResponse
        default: throw PassboltError.serverError(status)
        }
        let created = try decodeBody(CreatedDTO.self, from: data)
        let resource = PassboltResource(id: created.id, name: draft.name, username: draft.username,
                                        uri: draft.uri, resourceTypeId: typeIdUsed)
        index.append(resource)
        return resource
    }

    // MARK: Update

    private struct ResourceDetailDTO: Decodable {
        let resource_type_id: String?
        let metadata: String?
        let metadata_key_id: String?
        let metadata_key_type: String?
    }
    private struct AccessUserDTO: Decodable { let id: String; let gpgkey: GpgKeyDTO? }

    private func fetchResource(_ id: String) async throws -> ResourceDetailDTO {
        try await get("/resources/\(id).json", failure: .notFound)
    }

    /// Every user who can open the resource, directly or through a group.
    private func usersWithAccess(to id: String) async throws -> [AccessUserDTO] {
        try await get("/users.json?filter[has-access]=\(id)&contain[gpgkey]=1", failure: .invalidResponse)
    }

    /// True for v5 types, false for v4; anything else (custom fields, standalone TOTP, ...) is not editable here.
    private func editFormat(typeId: String?) throws -> Bool {
        switch typeId.flatMap({ typeSlugs[$0] }) {
        case "v5-default", "v5-default-with-totp": return true
        case "password-and-description", "password-description-totp": return false
        default: throw PassboltError.editUnsupported
        }
    }

    private func decryptMetadata(_ dto: ResourceDetailDTO) throws -> [String: Any] {
        guard let armored = dto.metadata, let userKey else { throw PassboltError.decryptionFailed }
        let decryptor: PGPKeyHandle? = dto.metadata_key_type == "user_key" ? userKey
            : dto.metadata_key_id.flatMap { metadataKeys[$0] }
        guard let decryptor, let plain = try? decryptor.decrypt(armored, verifyingWith: nil),
              let json = try? JSONSerialization.jsonObject(with: plain) as? [String: Any] else {
            throw PassboltError.decryptionFailed
        }
        return json
    }

    public func editableDraft(for resource: PassboltResource) async throws -> NewResource {
        let isV5 = try editFormat(typeId: resource.resourceTypeId)
        let secret = try await getSecret(for: resource)
        var notes = secret.description ?? ""
        if isV5 {
            let current = try await fetchResource(resource.id)
            notes = try decryptMetadata(current)["description"] as? String ?? ""
        }
        return NewResource(name: resource.name, uri: resource.uri, username: resource.username,
                           password: secret.password ?? "", totpSecret: secret.totp?.secretKey ?? "", notes: notes)
    }

    /// SECURITY CRITICAL: the server requires the secret re-encrypted for every user with access.
    public func updateResource(_ resource: PassboltResource, with draft: NewResource) async throws -> PassboltResource {
        guard let key = userKey else { throw PassboltError.notConfigured }
        let current = try await fetchResource(resource.id)
        let isV5 = try editFormat(typeId: current.resource_type_id ?? resource.resourceTypeId)
        let wantsTOTP = !draft.totpSecret.isEmpty
        let targetSlug = isV5 ? (wantsTOTP ? "v5-default-with-totp" : "v5-default")
                              : (wantsTOTP ? "password-description-totp" : "password-and-description")
        guard let typeId = typeSlugs.first(where: { $0.value == targetSlug })?.key else { throw PassboltError.editUnsupported }

        var recipients: [(id: String, key: String)] = []
        for u in try await usersWithAccess(to: resource.id) {
            guard let armored = u.gpgkey?.armored_key else { throw PassboltError.editUnsupported }
            recipients.append((u.id, armored))
        }
        guard let ownKey = recipients.first(where: { $0.id == userId })?.key else { throw PassboltError.editUnsupported }

        // Keep the existing TOTP parameters when the key itself is unchanged.
        let old = (try? await getSecret(for: resource))?.totp
        var secret: [String: Any] = ["password": draft.password]
        if wantsTOTP {
            let same = old?.secretKey == draft.totpSecret
            secret["totp"] = ["secret_key": draft.totpSecret, "algorithm": same ? old!.algorithm : "SHA1",
                              "digits": same ? old!.digits : 6, "period": same ? old!.period : 30] as [String: Any]
        }

        var body: [String: Any] = ["resource_type_id": typeId]
        if isV5 {
            secret["object_type"] = "PASSBOLT_SECRET_DATA"
            var metadata = try decryptMetadata(current)   // preserves fields this form doesn't edit
            let oldURIs = metadata["uris"] as? [String] ?? []
            metadata["object_type"] = "PASSBOLT_RESOURCE_METADATA"
            metadata["resource_type_id"] = typeId
            metadata["name"] = draft.name
            metadata["username"] = draft.username
            metadata["uris"] = (draft.uri.isEmpty ? [] : [draft.uri]) + oldURIs.dropFirst()
            metadata["uri"] = nil
            metadata["description"] = draft.notes.isEmpty ? nil : draft.notes
            let metadataTarget: (armored: String, id: Any, type: String)
            if current.metadata_key_type == "user_key" {
                metadataTarget = (ownKey, current.metadata_key_id ?? NSNull(), "user_key")
            } else if let shared = sharedMetadataKey {
                metadataTarget = (shared.armored, shared.id, "shared_key")
            } else {
                throw PassboltError.editUnsupported
            }
            body["metadata"] = try key.signAndEncrypt(try JSONSerialization.data(withJSONObject: metadata),
                                                      to: metadataTarget.armored)
            body["metadata_key_id"] = metadataTarget.id
            body["metadata_key_type"] = metadataTarget.type
        } else {
            secret["description"] = draft.notes
            body["name"] = draft.name; body["username"] = draft.username; body["uri"] = draft.uri
        }

        let plainSecret = try JSONSerialization.data(withJSONObject: secret)
        body["secrets"] = try recipients.map { ["user_id": $0.id, "data": try key.signAndEncrypt(plainSecret, to: $0.key)] }

        let (_, status) = try await send("PUT", "/resources/\(resource.id).json", body: body, token: accessToken)
        switch status {
        case 200, 201: break
        case 401: throw PassboltError.authenticationExpired
        case 400: throw PassboltError.invalidResponse
        case 404: throw PassboltError.notFound
        default: throw PassboltError.serverError(status)
        }
        let updated = PassboltResource(id: resource.id, name: draft.name, username: draft.username,
                                       uri: draft.uri, resourceTypeId: typeId)
        if let i = index.firstIndex(where: { $0.id == resource.id }) { index[i] = updated } else { index.append(updated) }
        return updated
    }

    // MARK: HTTP helpers

    private struct Envelope<T: Decodable>: Decodable { let body: T }

    private func decodeBody<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        do { return try JSONDecoder().decode(Envelope<T>.self, from: data).body }
        catch { throw PassboltError.invalidResponse }
    }

    private func get<T: Decodable>(_ path: String, token: String? = nil, failure: PassboltError) async throws -> T {
        let tok = token ?? accessToken
        let (data, status) = try await send("GET", path, body: nil, token: tok)
        switch status {
        case 200: return try decodeBody(T.self, from: data)
        case 401: throw tok == nil ? failure : PassboltError.authenticationExpired
        case 404: throw failure
        default: throw PassboltError.serverError(status)
        }
    }

    private func send(_ method: String, _ path: String, body: Any?, token: String?) async throws -> (Data, Int) {
        guard let url = URL(string: baseURL.absoluteString.trimmingSuffix("/") + path) else { throw PassboltError.invalidServerURL }
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        if let token { req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        if let body {
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = try JSONSerialization.data(withJSONObject: body)
        }
        let (data, status) = try await transport.send(req)
        return (data, status)
    }
}

private extension String {
    func trimmingSuffix(_ s: String) -> String { hasSuffix(s) ? String(dropLast(s.count)) : self }
}
