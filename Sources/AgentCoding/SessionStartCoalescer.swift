#if os(macOS)
import Foundation

/// A new session asked for again — the same workspace, agent, folder,
/// clone, opening message, instructions, room and files — while the first
/// is still starting, or within `window` of its answer: the first's answer,
/// not a second session. Over a slow link (a fat client) the window doesn't
/// change for a while after Send, and a click or two more each started an
/// identical session. Only what a person starts goes through here (the
/// composer, a client's request); a delegation or the Switchboard may well
/// start two alike. A start still under way (an attached machine's, up to a
/// minute) is waited for; one that failed isn't remembered, so a retry goes
/// through. Each attempt owns its slot by a token: a late completion never
/// writes over the next attempt's.
final class SessionStartCoalescer: @unchecked Sendable {
    static let shared = SessionStartCoalescer()
    /// How long a finished start answers the same request.
    static let window: TimeInterval = 10
    /// Longest wait for a start still under way (an attached machine's
    /// control call allows 60 s).
    static let pendingWait: TimeInterval = 75

    private let cond = NSCondition()
    private var entries: [String: Entry] = [:]
    private struct Entry {
        var token: UUID
        var startedAt: Date
        var reply: [String: Any]?   // nil: still starting
        var finishedAt: Date?
    }

    /// What makes two starts "the same". `attachments`: name and byte size
    /// of each dropped file.
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
            attachments: req.attachments.map { attachment(name: $0.name, bytes: $0.data.count) })
    }

    /// A start on an attached machine from this host's window, keyed on what
    /// it sends (no instructions, no folders) — as the hub keys a client's
    /// same start from its body, so the two share one slot.
    static func machineKey(_ req: AgentSessionRequest, machine: UUID, room: UUID?) -> String {
        var keyed = req
        keyed.profileID = machine
        keyed.roomID = room
        keyed.instructions = nil
        keyed.attachments = req.attachments.filter { $0.folder == nil }
        return key(keyed)
    }

    /// One dropped file in a key; a wire request's base64 is counted decoded,
    /// so the composer's and a client's same file match.
    static func attachment(name: String, bytes: Int) -> String { "\(name):\(bytes)" }
    static func attachment(wire: [String: Any]) -> String {
        let b64 = wire["data"] as? String ?? ""
        return attachment(name: wire["name"] as? String ?? "",
                          bytes: Data(base64Encoded: b64)?.count ?? b64.utf8.count)
    }

    /// The reply to remember for `key` right now, or nil (none, or too old).
    /// Under the lock.
    private func finishedReply(_ key: String, now: Date) -> [String: Any]? {
        guard let e = entries[key], let reply = e.reply, let at = e.finishedAt,
              now.timeIntervalSince(at) < Self.window else { return nil }
        return reply
    }

    private func prune(now: Date) {
        entries = entries.filter { _, e in
            if let at = e.finishedAt { return now.timeIntervalSince(at) < Self.window }
            return now.timeIntervalSince(e.startedAt) < Self.pendingWait * 2
        }
    }

    /// `work`'s reply for `key` — or the same start's: the one under way
    /// (waited for), or one finished within `window`.
    func run(_ key: String, now: () -> Date = Date.init, _ work: () -> [String: Any]) -> [String: Any] {
        cond.lock()
        prune(now: now())
        let giveUp = Date().addingTimeInterval(Self.pendingWait)
        while let e = entries[key], e.reply == nil, Date() < giveUp {
            cond.wait(until: min(giveUp, Date().addingTimeInterval(1)))
        }
        if let reply = finishedReply(key, now: now()) { cond.unlock(); return reply }
        let token = UUID()
        entries[key] = Entry(token: token, startedAt: now())
        cond.unlock()
        let reply = work()
        settle(key, token: token, reply: reply.isEmpty || reply["error"] != nil ? nil : reply, now: now())
        return reply
    }

    /// What `claim` found.
    enum Claim {
        /// Start it: `finish` with this token.
        case mine(UUID)
        /// The same start is under way (here or through the hub): ask again
        /// in a moment.
        case underWay
        /// The same start finished within `window`: its reply (with the
        /// session id) — open that session, don't start another.
        case done([String: Any])
    }

    /// For a start that can't wait here (the main thread's async one).
    func claim(_ key: String, now: Date = Date()) -> Claim {
        cond.lock(); defer { cond.unlock() }
        prune(now: now)
        if let reply = finishedReply(key, now: now) { return .done(reply) }
        if let e = entries[key], e.reply == nil { return .underWay }
        let token = UUID()
        entries[key] = Entry(token: token, startedAt: now)
        return .mine(token)
    }

    /// A claimed start's end: its reply (with the session id) is what the
    /// same request gets for `window`; nil (it failed) forgets it.
    func finish(_ key: String, token: UUID, reply: [String: Any]?, now: Date = Date()) {
        settle(key, token: token, reply: reply, now: now)
    }

    private func settle(_ key: String, token: UUID, reply: [String: Any]?, now: Date) {
        cond.lock()
        // Only the attempt that owns the slot: a late one (pruned, replaced)
        // never fills or clears the next attempt's.
        if entries[key]?.token == token {
            if let reply {
                entries[key]?.reply = reply
                entries[key]?.finishedAt = now
            } else {
                entries[key] = nil
            }
        }
        cond.broadcast()
        cond.unlock()
    }
}
#endif
