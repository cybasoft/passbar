import SwiftUI
import PassBarKit

struct RootView: View {
    @ObservedObject var model: AppModel
    let actions: AppActions

    var body: some View {
        VStack(spacing: 0) {
            switch model.state {
            case .unconfigured: SetupView(model: model)
            case .locked, .unlocking: LockedView(model: model)
            case .awaitingMFA: MFAView(model: model)
            case .unlocked:
                if model.editingResource != nil { CreateView(model: model) }
                else if let detail = model.detail { DetailView(model: model, detail: detail) }
                else if model.isCreating { CreateView(model: model) }
                else { SearchView(model: model, actions: actions) }
            }
            if let err = model.errorMessage { ErrorBar(message: err) { model.dismissError() } }
            FooterBar(model: model, actions: actions)
        }
        .frame(width: 360, height: 480)
        .onExitCommand { actions.close() }
        .background(shortcuts)
    }

    private var shortcuts: some View {
        Group {
            Button("") { actions.openSettings() }.keyboardShortcut(",", modifiers: .command)
            Button("") { actions.quit() }.keyboardShortcut("q", modifiers: .command)
        }.opacity(0).accessibilityHidden(true)
    }
}

struct ErrorBar: View {
    let message: String
    let dismiss: () -> Void
    var body: some View {
        HStack {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
            Text(message).font(.callout).lineLimit(2)
            Spacer()
            Button(action: dismiss) { Image(systemName: "xmark") }.buttonStyle(.plain).accessibilityLabel("Dismiss error")
        }
        .padding(8).background(.quaternary)
    }
}

struct FooterBar: View {
    @ObservedObject var model: AppModel
    let actions: AppActions
    var body: some View {
        Divider()
        HStack {
            if model.state == .unlocked {
                Button { Task { await model.lock() } } label: { Label("Lock", systemImage: "lock") }
            }
            Spacer()
            Button { actions.openSettings() } label: { Image(systemName: "gearshape") }
                .accessibilityLabel("Settings")
            Button { actions.quit() } label: { Image(systemName: "power") }
                .accessibilityLabel("Quit")
        }
        .buttonStyle(.plain).padding(.horizontal, 12).padding(.vertical, 8)
    }
}

struct MFAView: View {
    @ObservedObject var model: AppModel
    @State private var code = ""
    @State private var busy = false
    @FocusState private var focused: Bool

    var body: some View {
        VStack(spacing: 12) {
            Spacer()
            Image(systemName: "lock.shield.fill").font(.system(size: 40)).foregroundStyle(.secondary)
            Text("Verification code").font(.title2.bold())
            Text("Enter the code from your authenticator app.").foregroundStyle(.secondary)
            TextField("123456", text: $code)
                .textFieldStyle(.roundedBorder).multilineTextAlignment(.center)
                .font(.title3.monospacedDigit()).frame(width: 140)
                .focused($focused).onSubmit(submit)
            HStack {
                Button("Cancel") { Task { await model.cancelMFA() } }
                Button("Verify", action: submit)
                    .keyboardShortcut(.defaultAction)
                    .disabled(busy || code.filter(\.isNumber).count < 6)
            }
            if busy { ProgressView().controlSize(.small) }
            Spacer()
        }
        .frame(maxWidth: .infinity)
        .onAppear { focused = true }
    }

    private func submit() {
        guard !busy, code.filter(\.isNumber).count >= 6 else { return }
        busy = true
        let entered = code
        Task {
            await model.submitMFA(entered)
            code = ""; busy = false
        }
    }
}

struct LockedView: View {
    @ObservedObject var model: AppModel
    var body: some View {
        VStack(spacing: 12) {
            Spacer()
            Image(systemName: "lock.fill").font(.system(size: 40)).foregroundStyle(.secondary)
            Text("PassBar").font(.title2.bold())
            Text("Unlock to search your vault.").foregroundStyle(.secondary)
            if model.state == .unlocking {
                ProgressView(model.isLoading ? "Loading vault…" : "Unlocking…")
            } else {
                Button("Unlock") { Task { await model.unlock() } }
                    .keyboardShortcut(.defaultAction).controlSize(.large)
            }
            Spacer()
        }
        .frame(maxWidth: .infinity)
        // Only the first launch prompts by itself; after any lock the user unlocks explicitly.
        .task { if model.state == .locked && model.shouldAutoPromptUnlock { await model.unlock() } }
    }
}
