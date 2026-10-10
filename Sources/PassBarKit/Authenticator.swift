import Foundation
import LocalAuthentication

/// Local user presence check (Touch ID, Apple Watch or the Mac login password).
public protocol LocalAuthenticator: Sendable {
    func authenticate(reason: String) async throws
}

public struct SystemAuthenticator: LocalAuthenticator {
    public init() {}
    public func authenticate(reason: String) async throws {
        let ctx = LAContext()
        var err: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &err) else { throw PassboltError.biometricsFailed }
        do {
            guard try await ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) else {
                throw PassboltError.biometricsFailed
            }
        } catch { throw PassboltError.biometricsFailed }
    }
}
