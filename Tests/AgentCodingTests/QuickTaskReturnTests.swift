import AppKit
import SwiftUI
import Testing
@testable import bromure_ac

@Suite("Quick task: Return adds", .serialized)
@MainActor
struct QuickTaskReturnTests {
    private final class Panel: NSPanel {
        override var canBecomeKey: Bool { true }
    }

    private func spin(_ s: TimeInterval) {
        RunLoop.main.run(until: Date().addingTimeInterval(s))
    }

    private func key(_ p: NSWindow, _ ch: String, code: UInt16, mods: NSEvent.ModifierFlags = []) {
        for t in [NSEvent.EventType.keyDown, .keyUp] {
            let e = NSEvent.keyEvent(with: t, location: .zero, modifierFlags: mods, timestamp: 0,
                                     windowNumber: p.windowNumber, context: nil, characters: ch,
                                     charactersIgnoringModifiers: ch, isARepeat: false, keyCode: code)!
            NSApp.sendEvent(e)
        }
        spin(0.1)
    }

    @Test("typed title + ↩ reaches onAdd")
    func returnAdds() {
        _ = NSApplication.shared
        var added: [(String, Bool)] = []
        let view = QuickTaskView(choices: TaskAssigneeChoices(sessions: [], rooms: []), here: nil,
                                 folder: "~", workspaceName: "W", initialAssignment: nil,
                                 onAdd: { t, _, _, keep in added.append((t, keep)) }, onClose: {})
        let p = Panel(contentRect: NSRect(x: 0, y: 0, width: 800, height: 700),
                      styleMask: [.borderless, .fullSizeContentView], backing: .buffered, defer: false)
        p.contentView = NSHostingView(rootView: view.padding(.top, 16)
            .frame(width: 800, height: 700, alignment: .top))
        p.makeKeyAndOrderFront(nil)
        spin(0.5)
        print("first responder:", String(describing: p.firstResponder))
        for c in "fix it" { key(p, String(c), code: 0) }
        key(p, "\r", code: 36)
        print("added:", added)
        #expect(added.map(\.0) == ["fix it"])
        p.orderOut(nil)
    }

    /// Board report: one ⇥ opens Details, and ↩ there did nothing — the
    /// only way on was ⇥⇥ into the full editor.
    @Test("↩ in Details adds the task; ⌘↩ adds and keeps going; ⌥↩ is a new line")
    func returnInDetailsAdds() {
        _ = NSApplication.shared
        var added: [(String, String, Bool)] = []
        let view = QuickTaskView(choices: TaskAssigneeChoices(sessions: [], rooms: []), here: nil,
                                 folder: "~", workspaceName: "W", initialAssignment: nil,
                                 onAdd: { t, d, _, keep in added.append((t, d, keep)) }, onClose: {})
        let p = Panel(contentRect: NSRect(x: 0, y: 0, width: 800, height: 700),
                      styleMask: [.borderless, .fullSizeContentView], backing: .buffered, defer: false)
        p.contentView = NSHostingView(rootView: view.padding(.top, 16)
            .frame(width: 800, height: 700, alignment: .top))
        p.makeKeyAndOrderFront(nil)
        spin(0.5)
        for c in "one" { key(p, String(c), code: 0) }
        key(p, "\t", code: 48)
        spin(0.3)
        for c in "a" { key(p, String(c), code: 0) }
        key(p, "\r", code: 36, mods: .option)
        for c in "b" { key(p, String(c), code: 0) }
        key(p, "\r", code: 36, mods: .command)
        // Kept open, title focused again: a second one, details and ↩.
        for c in "two" { key(p, String(c), code: 0) }
        key(p, "\t", code: 48)
        spin(0.3)
        for c in "c" { key(p, String(c), code: 0) }
        key(p, "\r", code: 36)
        #expect(added.map(\.0) == ["one", "two"])
        #expect(added.map(\.1) == ["a\nb", "c"])
        #expect(added.map(\.2) == [true, false])
        p.orderOut(nil)
    }
}
