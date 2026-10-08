import SwiftUI
import PassBarKit

/// New-credential / edit form. Drafts live in the model so they survive the popover closing.
struct CreateView: View {
    @ObservedObject var model: AppModel
    @State private var revealPassword = false
    @State private var busy = false

    private var isEditing: Bool { model.editingResource != nil }
    private var form: Binding<NewResource> { isEditing ? $model.editDraft : $model.draft }

    private var canSave: Bool {
        !busy && !form.wrappedValue.name.trimmingCharacters(in: .whitespaces).isEmpty && !form.wrappedValue.password.isEmpty
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Button { back() } label: { Image(systemName: "chevron.left") }
                    .buttonStyle(.plain).accessibilityLabel(isEditing ? "Cancel editing" : "Back to passwords")
                    .keyboardShortcut(.escape, modifiers: [])
                Text(isEditing ? "Edit password" : "New password").font(.system(size: 18, weight: .bold))
                Spacer()
                if busy { ProgressView().controlSize(.small) }
                Button("Save") { save() }
                    .keyboardShortcut(.defaultAction).disabled(!canSave)
            }
            .padding(.horizontal, 16).padding(.vertical, 12)
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    field("Name") { TextField("Name", text: form.name) }
                    field("URL") { TextField("https://", text: form.uri) }
                    field("Username") { TextField("Username", text: form.username) }
                    field("Password") {
                        HStack {
                            Group {
                                if revealPassword { TextField("Password", text: form.password) }
                                else { SecureField("Password", text: form.password) }
                            }
                            Button { revealPassword.toggle() } label: { Image(systemName: revealPassword ? "eye.slash" : "eye") }
                                .buttonStyle(.plain).accessibilityLabel(revealPassword ? "Hide password" : "Show password")
                        }
                    }
                    field("TOTP key (optional)") { TextField("Base32 secret", text: form.totpSecret) }
                    field("Notes (optional)") {
                        TextEditor(text: form.notes).font(.body).frame(height: 64).scrollContentBackground(.hidden)
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

    private func back() {
        if isEditing { model.cancelEdit() } else { model.isCreating = false }
    }

    private func save() {
        busy = true
        let toSave = model.draft
        Task {
            if isEditing { _ = await model.saveEdit() } else { _ = await model.createResource(toSave) }
            busy = false
        }
    }
}
