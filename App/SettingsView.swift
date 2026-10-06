import SwiftUI
import ServiceManagement
import PassboltKit

struct SettingsView: View {
    @ObservedObject var model: AppModel
    var body: some View {
        TabView {
            GeneralTab(prefs: model.preferences).tabItem { Label("General", systemImage: "gearshape") }
            PassboltTab(model: model).tabItem { Label("Passbolt", systemImage: "key") }
            SecurityTab(model: model).tabItem { Label("Security", systemImage: "lock.shield") }
        }
        .frame(width: 440, height: 300)
    }
}

struct GeneralTab: View {
    @ObservedObject var prefs: Preferences
    @State private var launchAtLogin = SMAppService.mainApp.status == .enabled
    @State private var loginError = false
    var body: some View {
        Form {
            Toggle("Launch at login", isOn: $launchAtLogin)
                .onChange(of: launchAtLogin) { _, on in
                    do { on ? try SMAppService.mainApp.register() : try SMAppService.mainApp.unregister(); loginError = false }
                    catch { loginError = true; launchAtLogin = SMAppService.mainApp.status == .enabled }
                }
            if loginError { Text("Could not change login item.").font(.caption).foregroundStyle(.red) }
            Picker("Keyboard shortcut", selection: $prefs.hotKey) {
                ForEach(HotKeyManager.presets, id: \.id) { Text($0.label).tag($0.id) }
            }
            TimeoutPicker(title: "Clear clipboard after", value: $prefs.clipboardTimeout,
                          options: [(0, "Never"), (10, "10 seconds"), (30, "30 seconds"), (60, "1 minute"), (120, "2 minutes")])
            TimeoutPicker(title: "Auto-lock after", value: $prefs.autoLockMinutes,
                          options: [(0, "Never"), (1, "1 minute"), (5, "5 minutes"), (15, "15 minutes"), (60, "1 hour")])
        }.padding()
    }
}

struct TimeoutPicker: View {
    let title: String
    @Binding var value: Double
    let options: [(Double, String)]
    var body: some View {
        Picker(title, selection: $value) { ForEach(options, id: \.0) { Text($0.1).tag($0.0) } }
    }
}

struct PassboltTab: View {
    @ObservedObject var model: AppModel
    var body: some View {
        Form {
            LabeledContent("Server", value: model.preferences.serverURL.isEmpty ? "Not configured" : model.preferences.serverURL)
            LabeledContent("User ID", value: model.preferences.userId.isEmpty ? "—" : model.preferences.userId)
            LabeledContent("Status", value: statusText)
            HStack {
                if model.state == .unlocked {
                    Button("Lock") { Task { await model.lock() } }
                    Button("Re-authenticate") { Task { await model.lock(); await model.unlock() } }
                } else if model.state == .locked {
                    Button("Unlock") { Task { await model.unlock() } }
                }
            }
            if model.state == .unconfigured {
                Text("Open the menu-bar icon to connect.").font(.caption).foregroundStyle(.secondary)
            }
            if let e = model.errorMessage { Text(e).font(.caption).foregroundStyle(.red) }
        }.padding()
    }
    private var statusText: String {
        switch model.state {
        case .unconfigured: return "Not configured"
        case .locked: return "Locked"
        case .unlocking: return "Unlocking…"
        case .unlocked: return "Authenticated"
        }
    }
}

struct SecurityTab: View {
    @ObservedObject var model: AppModel
    @State private var confirmClear = false
    var body: some View {
        Form {
            Button("Lock now") { Task { await model.lock() } }.disabled(model.state != .unlocked)
            Button("Clear cached data") { model.clearCachedData() }
            Text("Resource names are kept in memory only while unlocked. Nothing decrypted is written to disk.")
                .font(.caption).foregroundStyle(.secondary)
            Divider()
            Button("Clear Keychain credentials…", role: .destructive) { confirmClear = true }
            Text("Removes your stored private key and passphrase. You will need to set up again.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .padding()
        .confirmationDialog("Remove stored key and passphrase from the Keychain?", isPresented: $confirmClear) {
            Button("Clear credentials", role: .destructive) { Task { await model.clearKeychainCredentials() } }
        }
    }
}
