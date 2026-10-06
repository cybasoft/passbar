import Foundation
import Pgpbridge

/// An unlocked OpenPGP private key held in memory.
/// SECURITY CRITICAL: wraps live private-key material. Call `close()` when done.
public protocol PGPKeyHandle: AnyObject, Sendable {
    var fingerprint: String { get }
    /// Decrypts an armored message. If `publicKey` is given the signature must verify.
    func decrypt(_ armoredMessage: String, verifyingWith publicKey: String?) throws -> Data
    func signAndEncrypt(_ message: Data, to publicKey: String) throws -> String
    func close()
}

public protocol PGPProvider: Sendable {
    func openKey(armored: String, passphrase: String) throws -> PGPKeyHandle
}

/// All OpenPGP work is delegated to ProtonMail's GopenPGP through the small
/// wrapper in /PGPBridge. This app implements no cryptographic algorithms.
public struct GopenPGPProvider: PGPProvider {
    public init() {}

    public func openKey(armored: String, passphrase: String) throws -> PGPKeyHandle {
        var error: NSError?
        guard let key = PgpbridgeOpenPrivateKey(armored, Data(passphrase.utf8), &error) else {
            if error?.localizedDescription == "wrong passphrase" { throw PassboltError.wrongPassphrase }
            throw PassboltError.invalidKey
        }
        return GopenPGPKey(key)
    }
}

private final class GopenPGPKey: PGPKeyHandle, @unchecked Sendable {
    private let key: PgpbridgeKey
    init(_ key: PgpbridgeKey) { self.key = key }

    var fingerprint: String { key.fingerprint() }

    func decrypt(_ armoredMessage: String, verifyingWith publicKey: String?) throws -> Data {
        do { return try key.decrypt(armoredMessage, verifyWithPublicKey: publicKey ?? "") }
        catch { throw PassboltError.decryptionFailed }
    }

    func signAndEncrypt(_ message: Data, to publicKey: String) throws -> String {
        var error: NSError?
        let armored = key.signAndEncrypt(message, recipientPublicKey: publicKey, error: &error)
        if error != nil { throw PassboltError.decryptionFailed }
        return armored
    }

    func close() { key.close() }
}
