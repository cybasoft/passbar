import SwiftUI
import PassBarKit

/// New-credential / edit form. Drafts live in the model so they survive the popover closing.
struct CreateView: View {
    @ObservedObject var model: AppModel
    @State private var revealPassword = false
    @State private var busy = false
    @State private var additionalURIs = ""

    private var isEditing: Bool { model.editingResource != nil }
    private var form: Binding<NewResource> { isEditing ? $model.editDraft : $model.draft }

    private func parsedURIs(_ value: String) -> [String] {
        value.components(separatedBy: .newlines).map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
        }.filter { !$0.isEmpty }
    }

    private var canSave: Bool {
        !busy && !form.wrappedValue.name.trimmingCharacters(in: .whitespaces).isEmpty && !form.wrappedValue.password.isEmpty
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Button { back() } label: {
                    Image(systemName: "chevron.left").font(.system(size: 16, weight: .semibold))
                        .frame(width: 44, height: 36).contentShape(Rectangle())
                }
                    .buttonStyle(.plain).accessibilityLabel(isEditing ? "Cancel editing" : "Back to passwords")
                    .keyboardShortcut(.escape, modifiers: [])
                Text(isEditing ? "Edit password" : "New password").font(.system(size: 18, weight: .bold))
                Spacer()
                if busy { ProgressView().controlSize(.small) }
                Button("Save") { save() }
                    .keyboardShortcut(.defaultAction).disabled(!canSave)
            }
            .padding(.horizontal, 16).padding(.vertical, 12)
            if isEditing, let host = model.browserContext?.host {
                Text("Updating the credential used on \(host)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 16)
                    .padding(.bottom, 8)
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    field("Name") { TextField("Name", text: form.name) }
                    field("URL") {
                        TextField("https://", text: form.uri)
                            .onChange(of: form.uri.wrappedValue) { _, main in
                                var all = main.isEmpty ? [] : [main]
                                all.append(contentsOf: parsedURIs(additionalURIs).filter { $0 != main })
                                form.uris.wrappedValue = all
                            }
                    }
                    field("Additional URLs (one per line)") {
                        TextEditor(text: $additionalURIs)
                            .frame(height: 48)
                            .scrollContentBackground(.hidden)
                            .onChange(of: additionalURIs) { _, value in
                                let extras = parsedURIs(value)
                                var all = form.uri.wrappedValue.isEmpty ? [] : [form.uri.wrappedValue]
                                all.append(contentsOf: extras.filter { $0 != form.uri.wrappedValue })
                                if form.uri.wrappedValue.isEmpty, let first = extras.first {
                                    form.uri.wrappedValue = first
                                   all = [first] + extras.dropFirst().filter { $0 != first }
                                }
                                form.uris.wrappedValue = all
                            }
                    }
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
                    field("Notes (optional, encrypted)") {
                        TextEditor(text: form.notes).font(.body).frame(height: 64).scrollContentBackground(.hidden)
                    }
                    field("Description (optional)") {
                        TextEditor(text: form.description).font(.body).frame(height: 48).scrollContentBackground(.hidden)
                    }
                }
                .padding(.horizontal, 16).padding(.bottom, 12)
            }
        }
        .disabled(busy)
        .onAppear {
            let existing = form.uris.wrappedValue
            let extras = existing.filter { $0 != form.uri.wrappedValue }
            additionalURIs = extras.joined(separator: "\n")
        }
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
