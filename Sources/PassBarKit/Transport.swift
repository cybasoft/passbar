import Foundation

/// Minimal HTTP abstraction so the API client can be tested with mock responses.
public protocol HTTPTransport: Sendable {
    func send(_ request: URLRequest) async throws -> (data: Data, status: Int)
    /// Drops any session state (cookies) once the client is done.
    func invalidate()
}

public extension HTTPTransport {
    func invalidate() {}
}

/// Real transport. Uses default TLS validation (no custom trust handling),
/// in-memory cookies only (Passbolt's MFA cookie), no disk cache, and refuses non-HTTPS redirects.
public final class URLSessionTransport: NSObject, HTTPTransport, URLSessionTaskDelegate, @unchecked Sendable {
    private var session: URLSession!

    public override init() {
        super.init()
        let cfg = URLSessionConfiguration.ephemeral
        cfg.urlCache = nil
        cfg.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        cfg.timeoutIntervalForRequest = 30
        cfg.tlsMinimumSupportedProtocolVersion = .TLSv12
        session = URLSession(configuration: cfg, delegate: self, delegateQueue: nil)
    }

    public func invalidate() { session.invalidateAndCancel() }

    public func send(_ request: URLRequest) async throws -> (data: Data, status: Int) {
        guard request.url?.scheme == "https" else { throw PassboltError.insecureServerURL }
        do {
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse else { throw PassboltError.invalidResponse }
            return (data, http.statusCode)
        } catch let error as PassboltError {
            throw error
        } catch let error as URLError {
            switch error.code {
            case .serverCertificateUntrusted, .serverCertificateHasBadDate, .serverCertificateHasUnknownRoot,
                 .serverCertificateNotYetValid, .secureConnectionFailed, .clientCertificateRejected:
                throw PassboltError.certificateInvalid
            default: throw PassboltError.connectionFailed
            }
        } catch { throw PassboltError.connectionFailed }
    }

    public func urlSession(_ session: URLSession, task: URLSessionTask,
                           willPerformHTTPRedirection response: HTTPURLResponse,
                           newRequest request: URLRequest) async -> URLRequest? {
        request.url?.scheme == "https" ? request : nil
    }
}
