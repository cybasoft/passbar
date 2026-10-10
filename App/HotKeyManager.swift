import Carbon.HIToolbox
import AppKit

/// Global shortcut via Carbon RegisterEventHotKey (works in the sandbox, needs no
/// accessibility permission, and cannot observe other keystrokes).
final class HotKeyManager {
    static let presets: [(id: String, label: String)] = [
        ("none", "None"), ("ctrl-opt-space", "⌃⌥Space"), ("ctrl-opt-p", "⌃⌥P"), ("cmd-shift-p", "⌘⇧P"),
    ]
    private var ref: EventHotKeyRef?
    private var handler: EventHandlerRef?
    private var action: (() -> Void)?

    func register(preset: String, action: @escaping () -> Void) {
        unregister()
        let spec: (UInt32, UInt32)?
        switch preset {
        case "ctrl-opt-space": spec = (UInt32(kVK_Space), UInt32(controlKey | optionKey))
        case "ctrl-opt-p": spec = (UInt32(kVK_ANSI_P), UInt32(controlKey | optionKey))
        case "cmd-shift-p": spec = (UInt32(kVK_ANSI_P), UInt32(cmdKey | shiftKey))
        default: spec = nil
        }
        guard let (code, mods) = spec else { return }
        self.action = action
        var type = EventTypeSpec(eventClass: OSType(kEventClassKeyboard), eventKind: UInt32(kEventHotKeyPressed))
        InstallEventHandler(GetApplicationEventTarget(), { _, _, ctx in
            guard let ctx else { return noErr }
            Unmanaged<HotKeyManager>.fromOpaque(ctx).takeUnretainedValue().action?()
            return noErr
        }, 1, &type, Unmanaged.passUnretained(self).toOpaque(), &handler)
        RegisterEventHotKey(code, mods, EventHotKeyID(signature: OSType(0x50424D42), id: 1),
                            GetApplicationEventTarget(), 0, &ref)
    }

    func unregister() {
        if let ref { UnregisterEventHotKey(ref) }
        if let handler { RemoveEventHandler(handler) }
        ref = nil; handler = nil
    }
}
