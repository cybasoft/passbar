import SwiftUI
import UniformTypeIdentifiers
import PassBarKit

/// One-time setup. The key is read from the recovery-kit file you choose and goes
/// straight to the Keychain once login succeeds.
struct SetupView: View {
    @ObservedObject var model: AppModel
    @State private var server = ""
    @State private var userId = ""
    @State private var passphrase = ""
    @State private var keyText: String?
    @State private var keyName = ""
    @State private var picking = false
    @State private var busy = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 10) {
                Text("Connect to Passbolt").font(.title3.bold())
                Text("Server URL").font(.caption).foregroundStyle(.secondary)
                TextField("https://passbolt.example.com", text: $server).textFieldStyle(.roundedBorder)
                Text("User ID").font(.caption).foregroundStyle(.secondary)
                TextField("UUID (see README)", text: $userId).textFieldStyle(.roundedBorder)
                Text("Private key").font(.caption).foregroundStyle(.secondary)
                HStack {
                    Button("Choose key file…") { picking = true }
                    Text(keyName.isEmpty ? "No file chosen" : keyName).foregroundStyle(.secondary).lineLimit(1)
                }
                Text("Key passphrase").font(.caption).foregroundStyle(.secondary)
                SecureField("Passphrase", text: $passphrase).textFieldStyle(.roundedBorder)
                Text("Stored in the macOS Keychain. Unlocking requires Touch ID or your Mac password.")
                    .font(.caption).foregroundStyle(.secondary)
                HStack {
                    Button("Connect") { connect() }
                        .keyboardShortcut(.defaultAction)
                        .disabled(busy || server.isEmpty || userId.isEmpty || keyText == nil)
                    if busy { ProgressView().controlSize(.small) }
                }
            }
            .padding(16)
        }
        .fileImporter(isPresented: $picking, allowedContentTypes: [.data, .text, .plainText]) { result in
            guard case .success(let url) = result else { return }
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            if let data = try? Data(contentsOf: url), data.count < 100_000,
               let text = String(data: data, encoding: .utf8), text.contains("BEGIN PGP PRIVATE KEY BLOCK") {
                keyText = text; keyName = url.lastPathComponent
            } else { keyText = nil; keyName = "Not a private key file" }
        }
    }

    private func connect() {
        guard let key = keyText else { return }
        busy = true
        Task {
            await model.configure(serverURL: server, userId: userId, privateKey: key, passphrase: passphrase)
            passphrase = ""; keyText = nil
            busy = false
        }
    }
}
