import SwiftUI
import PassBarKit

struct DetailView: View {
    @ObservedObject var model: AppModel
    let detail: ResourceDetail
    @State private var revealPassword = false
    @State private var revealTOTP = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Button { model.clearDetail() } label: { Image(systemName: "chevron.left") }
                    .buttonStyle(.plain).accessibilityLabel("Back to search")
                    .keyboardShortcut(.escape, modifiers: [])
                Text(detail.resource.name).font(.headline).lineLimit(1)
                Spacer()
            }
            .padding(12)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(Array(rows.enumerated()), id: \.element) { index, row in
                        if index > 0 { Divider() }
                        rowView(row).padding(.vertical, 10)
                    }
                }
                .padding(.horizontal, 12).padding(.vertical, 2)
            }
            // Cmd+C copies the password; Cmd+Shift+C the username.
            Group {
                Button("") { if let p = detail.secret.password { model.copy("password", value: p) } }
                    .keyboardShortcut("c", modifiers: .command)
                Button("") { model.copy("username", value: detail.resource.username) }
                    .keyboardShortcut("c", modifiers: [.command, .shift])
            }.opacity(0).frame(height: 0).accessibilityHidden(true)
        }
    }

    private enum Row { case username, password, totp, url }

    private var rows: [Row] {
        var r: [Row] = []
        if !detail.resource.username.isEmpty { r.append(.username) }
        if detail.secret.password != nil { r.append(.password) }
        if detail.secret.totp != nil { r.append(.totp) }
        if !detail.resource.uri.isEmpty { r.append(.url) }
        return r
    }

    @ViewBuilder private func rowView(_ row: Row) -> some View {
        switch row {
        case .username:
            field("Username", id: "username", shown: detail.resource.username, copy: detail.resource.username)
        case .password:
            if let pw = detail.secret.password {
                // The real password is never put in the accessibility tree while masked.
                field("Password", id: "password", shown: revealPassword ? pw : "••••••••••••",
                      copy: pw, accessibilityValue: revealPassword ? pw : "hidden", toggle: $revealPassword)
            }
        case .totp:
            let code = model.totpCode() ?? ""
            field("TOTP", id: "totp", shown: revealTOTP ? code : "••••••",
                  copy: code, accessibilityValue: revealTOTP ? code : "hidden", toggle: $revealTOTP,
                  copyValue: { model.totpCode() })
        case .url:
            urlRow
        }
    }

    private func field(_ label: String, id: String, shown: String, copy: String,
                       accessibilityValue: String? = nil, toggle: Binding<Bool>? = nil,
                       copyValue: (() -> String?)? = nil) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            HStack {
                Text(shown).font(.system(.body, design: .monospaced)).lineLimit(1).textSelection(.disabled)
                    .accessibilityLabel(label).accessibilityValue(accessibilityValue ?? shown)
                Spacer()
                if let toggle {
                    Button { toggle.wrappedValue.toggle() } label: {
                        Image(systemName: toggle.wrappedValue ? "eye.slash" : "eye")
                    }.buttonStyle(.plain).accessibilityLabel(toggle.wrappedValue ? "Hide \(label)" : "Show \(label)")
                }
                Button { model.copy(id, value: copyValue?() ?? copy) } label: {
                    Image(systemName: model.copiedField == id ? "checkmark" : "doc.on.doc")
                        .foregroundStyle(model.copiedField == id ? .green : .primary)
                }.buttonStyle(.plain).accessibilityLabel("Copy \(label)")
            }
        }
    }

    private var urlRow: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text("URL").font(.caption).foregroundStyle(.secondary)
            HStack {
                Text(detail.resource.uri).lineLimit(1).truncationMode(.middle)
                Spacer()
                Button { model.copy("url", value: detail.resource.uri) } label: {
                    Image(systemName: model.copiedField == "url" ? "checkmark" : "doc.on.doc")
                }.buttonStyle(.plain).accessibilityLabel("Copy URL")
                if let url = URL(string: detail.resource.uri), url.scheme == "https" || url.scheme == "http" {
                    Button { NSWorkspace.shared.open(url) } label: { Image(systemName: "arrow.up.right") }
                        .buttonStyle(.plain).accessibilityLabel("Open URL")
                }
            }
        }
    }
}
