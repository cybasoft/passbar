import SwiftUI
import PassBarKit

/// New-credential form. The draft lives in the model so it survives the popover closing.
struct CreateView: View {
    @ObservedObject var model: AppModel
    @State private var revealPassword = false
    @State private var busy = false

    private var canSave: Bool {
        !busy && !model.draft.name.trimmingCharacters(in: .whitespaces).isEmpty && !model.draft.password.isEmpty
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Button { model.isCreating = false } label: { Image(systemName: "chevron.left") }
                    .buttonStyle(.plain).accessibilityLabel("Back to passwords")
                    .keyboardShortcut(.escape, modifiers: [])
                Text("New password").font(.system(size: 18, weight: .bold))
                Spacer()
                if busy { ProgressView().controlSize(.small) }
                Button("Save") { save() }
                    .keyboardShortcut(.defaultAction).disabled(!canSave)
            }
            .padding(.horizontal, 16).padding(.vertical, 12)
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    field("Name") { TextField("Name", text: $model.draft.name) }
                    field("URL") { TextField("https://", text: $model.draft.uri) }
                    field("Username") { TextField("Username", text: $model.draft.username) }
                    field("Password") {
                        HStack {
                            Group {
                                if revealPassword { TextField("Password", text: $model.draft.password) }
                                else { SecureField("Password", text: $model.draft.password) }
                            }
                            Button { revealPassword.toggle() } label: { Image(systemName: revealPassword ? "eye.slash" : "eye") }
                                .buttonStyle(.plain).accessibilityLabel(revealPassword ? "Hide password" : "Show password")
                        }
                    }
                    field("TOTP key (optional)") { TextField("Base32 secret", text: $model.draft.totpSecret) }
                    field("Notes (optional)") {
                        TextEditor(text: $model.draft.notes).font(.body).frame(height: 64).scrollContentBackground(.hidden)
                    }
                }
                .padding(.horizontal, 16).padding(.bottom, 12)
            }
        }
        .disabled(busy)
    }

    private func field<Content: View>(_ label: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            content()
                .textFieldStyle(.plain)
                .padding(.horizontal, 10).padding(.vertical, 7)
                .background(RoundedRectangle(cornerRadius: 10).fill(Color.primary.opacity(0.08)))
        }
    }

    private func save() {
        busy = true
        let toSave = model.draft
        Task {
            _ = await model.createResource(toSave)
            busy = false
        }
    }
}
