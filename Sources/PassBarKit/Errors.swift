import Foundation

/// User-facing errors. Messages are fixed strings: they never include raw API
/// responses, tokens, keys or decrypted data.
public enum PassboltError: Error, Equatable, LocalizedError {
    case notConfigured
    case invalidServerURL
    case insecureServerURL
    case connectionFailed
    case certificateInvalid
    case authenticationFailed
    case authenticationExpired
    case serverError(Int)
    case invalidResponse
    case decryptionFailed
    case wrongPassphrase
    case invalidKey
    case biometricsFailed
    case keychain(Int32)
    case notFound

    public var errorDescription: String? {
        switch self {
        case .notConfigured: return "Your Passbolt instance is not configured yet."
        case .invalidServerURL: return "Your Passbolt server URL is not valid."
        case .insecureServerURL: return "Only https:// server URLs are allowed."
        case .connectionFailed: return "Unable to connect to Passbolt."
        case .certificateInvalid: return "Your Passbolt endpoint certificate could not be verified."
        case .authenticationFailed: return "Authentication failed. Check your user ID and key."
        case .authenticationExpired: return "Authentication expired. Please authenticate again."
        case .serverError(let code): return "Passbolt returned an error (HTTP \(code))."
        case .invalidResponse: return "Your Passbolt instance returned an unexpected response."
        case .decryptionFailed: return "Unable to decrypt resource."
        case .wrongPassphrase: return "The passphrase is incorrect."
        case .invalidKey: return "The private key could not be read."
        case .biometricsFailed: return "Unlock was cancelled or failed."
        case .keychain(let status): return "Keychain error (\(status))."
        case .notFound: return "Resource not found."
        }
    }
}
