import SwiftUI
import PassboltKit

struct RootView: View {
    @ObservedObject var model: AppModel
    let actions: AppActions

    var body: some View {
        VStack(spacing: 0) {
            switch model.state {
            case .unconfigured: SetupView(model: model)
            case .locked, .unlocking: LockedView(model: model)
            case .unlocked:
                if let detail = model.detail { DetailView(model: model, detail: detail) }
                else { SearchView(model: model, actions: actions) }
            }
            if let err = model.errorMessage { ErrorBar(message: err) { model.dismissError() } }
            FooterBar(model: model, actions: actions)
        }
        .frame(width: 400, height: 460)
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

struct LockedView: View {
    @ObservedObject var model: AppModel
    var body: some View {
        VStack(spacing: 12) {
            Spacer()
            Image(systemName: "lock.fill").font(.system(size: 40)).foregroundStyle(.secondary)
            Text("Passbolt").font(.title2.bold())
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
        .task { if model.state == .locked { await model.unlock() } }
    }
}
