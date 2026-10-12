#if os(macOS)
import Foundation

/// A new session asked for again — the same workspace, agent, folder,
/// clone, opening message, instructions, room and files — within
/// `window` of the first: the first's answer, not a second session. Over a
/// slow link (a fat client) the window doesn't change for a while after
/// Send, and a click or two more each started an identical session. Only
/// what a person starts goes through here (the composer, a client's
/// request); a delegation or the Switchboard may well start two alike.
/// A start still under way (an attached machine's, up to a minute) is
/// waited for; one that failed isn't remembered, so a retry goes through.
final class SessionStartCoalescer: @unchecked Sendable {
    static let shared = SessionStartCoalescer()
    static let window: TimeInterval = 10

    private let cond = NSCondition()
    private var entries: [String: Entry] = [:]
    private struct Entry {
        var reply: [String: Any]?   // nil: still starting
        var at: Date
    }

    /// What makes two starts "the same".
    static func key(profile: String, tool: String, cwd: String?, cloneURL: String?, message: String?,
                    instructions: String?, room: String?, attachments: [String]) -> String {
        func t(_ s: String?) -> String { (s ?? "").trimmingCharacters(in: .whitespacesAndNewlines) }
        var c = t(cwd)
        if c.isEmpty || c == "~/" { c = "~" }
        return [profile.uppercased(), tool, c, t(cloneURL), t(message), t(instructions),
                (room ?? "").uppercased(), attachments.joined(separator: "\u{1f}")]
            .joined(separator: "\u{1e}")
    }

    static func key(_ req: AgentSessionRequest) -> String {
        key(profile: req.profileID.uuidString, tool: req.tool.rawValue, cwd: req.cwd, cloneURL: req.cloneURL,
            message: req.openingMessage, instructions: req.instructions, room: req.roomID?.uuidString,
            attachments: req.attachments.map { "\($0.name):\($0.data.count)" })
    }

    /// `work`'s reply for `key`, or — the same start within `window` — the
    /// one before (waited for while it's still under way).
    func run(_ key: String, now: () -> Date = Date.init, _ work: () -> [String: Any]) -> [String: Any] {
        cond.lock()
        let t = now()
        entries = entries.filter { t.timeIntervalSince($0.value.at) < Self.window * 6 }
        while let e = entries[key], t.timeIntervalSince(e.at) < Self.window {
            if let reply = e.reply { cond.unlock(); return reply }
            cond.wait(until: Date().addingTimeInterval(1))
        }
        entries[key] = Entry(reply: nil, at: t)
        cond.unlock()
        let reply = work()
        cond.lock()
        if reply["error"] == nil { entries[key]?.reply = reply } else { entries[key] = nil }
        cond.broadcast()
        cond.unlock()
        return reply
    }

    /// For a start that can't wait here (the main thread's async one):
    /// false — the same start was asked for within `window`, drop this one.
    func claim(_ key: String, now: Date = Date()) -> Bool {
        cond.lock(); defer { cond.unlock() }
        if let e = entries[key], now.timeIntervalSince(e.at) < Self.window { return false }
        entries[key] = Entry(reply: nil, at: now)
        return true
    }

    /// A claimed start's end: a failed one is forgotten (a retry may go).
    func finish(_ key: String, ok: Bool) {
        cond.lock()
        if ok { entries[key]?.reply = ["ok": true] } else { entries[key] = nil }
        cond.broadcast()
        cond.unlock()
    }
}
#endif
