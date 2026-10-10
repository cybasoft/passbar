import Foundation
import AppKit

public protocol PasteboardProtocol: AnyObject {
    func string() -> String?
    func write(_ string: String)
    func clear()
}

/// Real pasteboard. Marks copied values as concealed so well-behaved clipboard
/// managers (those honouring nspasteboard.org) don't record them.
public final class SystemPasteboard: PasteboardProtocol {
    private let pb = NSPasteboard.general
    public init() {}
    public func string() -> String? { pb.string(forType: .string) }
    public func write(_ string: String) {
        pb.clearContents()
        pb.setString(string, forType: .string)
        pb.setString("", forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
    }
    public func clear() { pb.clearContents() }
}

/// SECURITY CRITICAL: places secrets on the system clipboard and removes them again.
/// The clear only happens if the clipboard STILL holds exactly what we put there,
/// so something another app copied in the meantime is never wiped.
@MainActor
public final class ClipboardManager {
    private let pasteboard: PasteboardProtocol
    private let sleep: (TimeInterval) async throws -> Void
    private var copied: String?
    private var task: Task<Void, Never>?

    public init(pasteboard: PasteboardProtocol,
                sleep: @escaping (TimeInterval) async throws -> Void = { try await Task.sleep(nanoseconds: UInt64($0 * 1_000_000_000)) }) {
        self.pasteboard = pasteboard
        self.sleep = sleep
    }

    /// `timeout <= 0` disables automatic clearing.
    public func copy(_ value: String, clearAfter timeout: TimeInterval) {
        task?.cancel()
        pasteboard.write(value)
        copied = value
        guard timeout > 0 else { return }
        task = Task { [weak self] in
            do { try await self?.sleep(timeout) } catch { return }
            self?.clearIfUnchanged()
        }
    }

    /// Clears the clipboard only if it still contains our last copied value.
    public func clearIfUnchanged() {
        task?.cancel(); task = nil
        defer { copied = nil }
        guard let copied, pasteboard.string() == copied else { return }
        pasteboard.clear()
    }
}
