import CryptoKit
import Foundation

/// The workspaces' Squelch settings as the proxy reads them, kept current
/// from every save of the profile list (`ACAppDelegate.profiles`): an edit
/// applies to the next request, no restart.
enum SquelchSettings {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var policies: [UUID: SquelchPolicy] = [:]

    static func update(_ new: [UUID: SquelchPolicy]) {
        lock.lock()
        let changed = new.filter { policies[$0.key] != $0.value }
        policies = new
        lock.unlock()
        for (id, p) in changed {
            FileHandle.standardError.write(Data("[squelch] \(p.enabled ? "on" : "off") for \(id.uuidString.prefix(8))\n".utf8))
        }
    }

    static func policy(for id: UUID) -> SquelchPolicy? {
        lock.lock(); defer { lock.unlock() }
        return policies[id]
    }
}

/// The savings record: per workspace, per agent conversation, per command and
/// per day. Each command output counts once, the first
/// time a request carries it (the conversation is resent every turn).
/// Persisted in Application Support; a cloud report is a delta since the
/// last one (`pendingCloudReport`, `SquelchCloud`).
final class SquelchLedger: @unchecked Sendable {
    static let shared = SquelchLedger(file: FileManager.default
        .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        .appendingPathComponent("BromureAC/squelch/ledger.json"))

    struct Workspace: Codable, Equatable {
        var total = SquelchTally()
        /// By the agent's own conversation id (what a session keeps as
        /// `agentTranscriptID`); requests that name none aren't here.
        var conversations: [String: SquelchTally] = [:]
        /// By command ("pytest", "npm install", "git push").
        var commands: [String: SquelchTally] = [:]
        /// By family (`Squelch.Family.rawValue`).
        var families: [String: SquelchTally] = [:]
        /// By day ("2026-10-19", the Mac's calendar), the last `keepDays`.
        var days: [String: SquelchTally] = [:]
        /// Outputs already counted (a digest of conversation and call id),
        /// oldest first, the last `keepCounted`: a long session's early
        /// outputs are still resent every turn.
        var counted: [String] = []
        /// What cloud reports already covered, by day.
        var reportedDays: [String: SquelchTally] = [:]
    }

    struct Snapshot: Codable, Equatable {
        var workspaces: [String: Workspace] = [:]
    }

    static let keepDays = 90
    static let keepCounted = 50_000
    static let keepCommands = 60
    static let keepConversations = 400

    private let file: URL?
    private let lock = NSLock()
    private var state = Snapshot()
    /// `Workspace.counted` as sets, built on first use.
    private var countedSets: [String: Set<String>] = [:]
    private var dirty = false
    private var saveScheduled = false
    /// Called (off the main thread) when a workspace's numbers change.
    var onChange: (@Sendable (UUID) -> Void)?

    init(file: URL?) {
        self.file = file
        if let file, let d = try? Data(contentsOf: file),
           let s = try? JSONDecoder().decode(Snapshot.self, from: d) {
            state = s
        }
    }

    /// Count what one request did. Outputs counted before (an earlier turn
    /// of the same conversation) are skipped.
    func record(_ o: SquelchRewriter.Outcome, profileID: UUID, conversation: String?, now: Date = Date()) {
        guard !o.seen.isEmpty else { return }
        let trims = Dictionary(o.trims.map { ($0.callID, $0) }, uniquingKeysWith: { a, _ in a })
        let day = Self.dayKey(now)
        lock.lock()
        let wid = profileID.uuidString
        var w = state.workspaces[wid] ?? Workspace()
        var counted = countedSets[wid] ?? Set(w.counted)
        var changed = false
        for (callID, raw) in o.seen.sorted(by: { $0.key < $1.key }) {
            let key = Self.countedKey(conversation: conversation, callID: callID)
            guard counted.insert(key).inserted else { continue }
            w.counted.append(key)
            var t = SquelchTally(outputs: 1, trimmed: 0, rawBytes: raw, keptBytes: raw)
            var family = Squelch.Family.other.rawValue
            var command = "other"
            if let trim = trims[callID] {
                t.trimmed = 1
                t.keptBytes = raw - (trim.rawBytes - trim.keptBytes)
                family = trim.family.rawValue
                command = Self.commandLabel(trim.command) ?? family
            }
            w.total = w.total + t
            if let conversation { w.conversations[conversation, default: SquelchTally()] = w.conversations[conversation, default: SquelchTally()] + t }
            // Commands and families only for what Squelch acted on: the
            // breakdown is "where the savings came from".
            if t.trimmed > 0 {
                w.commands[command] = (w.commands[command] ?? SquelchTally()) + t
                w.families[family] = (w.families[family] ?? SquelchTally()) + t
            }
            w.days[day] = (w.days[day] ?? SquelchTally()) + t
            changed = true
        }
        guard changed else { countedSets[wid] = counted; lock.unlock(); return }
        if w.counted.count > Self.keepCounted {
            let drop = w.counted.count - Self.keepCounted
            for k in w.counted.prefix(drop) { counted.remove(k) }
            w.counted.removeFirst(drop)
        }
        countedSets[wid] = counted
        Self.prune(&w)
        state.workspaces[wid] = w
        scheduleSaveLocked()
        let cb = onChange
        lock.unlock()
        cb?(profileID)
    }

    func workspace(_ id: UUID) -> Workspace? {
        lock.lock(); defer { lock.unlock() }
        return state.workspaces[id.uuidString]
    }

    func conversation(_ id: UUID, _ conversation: String) -> SquelchTally? {
        lock.lock(); defer { lock.unlock() }
        return state.workspaces[id.uuidString]?.conversations[conversation.lowercased()]
    }

    /// The workspace's numbers as rows and headers show them; nil before
    /// Squelch saw any command output there.
    func summary(_ id: UUID, commands: Int = 8, days: Int = 14, now: Date = Date()) -> SquelchSummary? {
        lock.lock(); defer { lock.unlock() }
        guard let w = state.workspaces[id.uuidString], !w.total.isEmpty else { return nil }
        let top = w.commands.sorted { $0.value.savedBytes != $1.value.savedBytes
            ? $0.value.savedBytes > $1.value.savedBytes : $0.key < $1.key }
            .prefix(commands).map { SquelchSummary.Entry(name: $0.key, tally: $0.value) }
        let cal = Calendar(identifier: .gregorian)
        let recent = (0..<days).reversed().compactMap { back -> SquelchSummary.Entry? in
            guard let d = cal.date(byAdding: .day, value: -back, to: now) else { return nil }
            let key = Self.dayKey(d)
            return SquelchSummary.Entry(name: key, tally: w.days[key] ?? SquelchTally())
        }
        return SquelchSummary(total: w.total, commands: top, days: recent)
    }

    /// All workspaces together.
    func grandTotal() -> SquelchTally {
        lock.lock(); defer { lock.unlock() }
        return state.workspaces.values.reduce(SquelchTally()) { $0 + $1.total }
    }

    /// Forget a workspace's numbers (it was deleted, or the user reset them).
    func reset(_ id: UUID) {
        lock.lock()
        state.workspaces[id.uuidString] = nil
        countedSets[id.uuidString] = nil
        scheduleSaveLocked()
        lock.unlock()
        onChange?(id)
    }

    // MARK: Cloud

    /// What a report to the Bromure cloud carries: per workspace, the
    /// savings since the last report, by day. Nothing sends it yet — the
    /// endpoint doesn't exist — `pendingCloudReport` is what the uploader will
    /// call (`SquelchCloud.sendPending`), and `SquelchCloud.sink` where it
    /// plugs in.
    struct CloudReport: Codable, Equatable {
        struct Row: Codable, Equatable {
            var workspaceID: String
            var day: String
            var outputs: Int
            var trimmed: Int
            var rawBytes: Int
            var keptBytes: Int
            /// bytes / 4, as everywhere Squelch counts tokens.
            var rawTokens: Int { rawBytes / 4 }
            var keptTokens: Int { keptBytes / 4 }
            var savedTokens: Int { max(0, rawBytes - keptBytes) / 4 }
        }
        var rows: [Row]
        var isEmpty: Bool { rows.isEmpty }
    }

    /// The savings not reported yet.
    func pendingCloudReport() -> CloudReport {
        lock.lock(); defer { lock.unlock() }
        var rows: [CloudReport.Row] = []
        for (id, w) in state.workspaces.sorted(by: { $0.key < $1.key }) {
            for (day, t) in w.days.sorted(by: { $0.key < $1.key }) {
                let d = t - (w.reportedDays[day] ?? SquelchTally())
                guard d.outputs > 0 else { continue }
                rows.append(.init(workspaceID: id, day: day, outputs: d.outputs, trimmed: d.trimmed,
                                  rawBytes: d.rawBytes, keptBytes: d.keptBytes))
            }
        }
        return CloudReport(rows: rows)
    }

    /// `report` reached the cloud: what it carried is never sent again
    /// (what came in since it was made still is).
    func markReported(_ report: CloudReport) {
        lock.lock(); defer { lock.unlock() }
        for row in report.rows {
            guard var w = state.workspaces[row.workspaceID] else { continue }
            w.reportedDays[row.day] = (w.reportedDays[row.day] ?? SquelchTally())
                + SquelchTally(outputs: row.outputs, trimmed: row.trimmed, rawBytes: row.rawBytes, keptBytes: row.keptBytes)
            state.workspaces[row.workspaceID] = w
        }
        if !report.isEmpty { scheduleSaveLocked() }
    }

    // MARK: Helpers

    /// "pytest", "npm install", "git push", "cargo test" — a command's first
    /// word, and its subcommand when it has one.
    static func commandLabel(_ command: String?) -> String? {
        guard let command else { return nil }
        let segments = Squelch.split(command, on: ["&&", "||", ";", "\n"]).map { $0.trimmingCharacters(in: .whitespaces) }
        guard let seg = segments.last(where: { s in
            let w = Squelch.words(of: s).first ?? ""
            return !["cd", "echo", "export", "source", "set", "true"].contains(w) && !w.isEmpty
        }) else { return nil }
        let w = Squelch.words(of: Squelch.split(seg, on: ["|"]).first ?? seg)
        guard let first = w.first else { return nil }
        let subcommanded: Set<String> = ["git", "npm", "pnpm", "yarn", "bun", "cargo", "go", "swift", "docker",
                                         "kubectl", "pip", "pip3", "uv", "poetry", "apt", "apt-get", "brew",
                                         "dotnet", "make", "gradle", "./gradlew", "mvn", "bundle", "deno",
                                         "python", "python3", "npx", "xcodebuild"]
        if subcommanded.contains(first), w.count > 1 {
            var sub = w[1]
            if sub == "-m" || sub == "run" || sub == "exec", w.count > 2 { sub = sub == "-m" ? w[2] : "\(sub) \(w[2])" }
            if !sub.hasPrefix("-") { return "\(first) \(sub)".prefix(40).description }
        }
        return String(first.prefix(40))
    }

    static func countedKey(conversation: String?, callID: String) -> String {
        let digest = SHA256.hash(data: Data(((conversation ?? "") + "|" + callID).utf8))
        return digest.prefix(9).map { String(format: "%02x", $0) }.joined()
    }

    static func dayKey(_ d: Date) -> String {
        let c = Calendar(identifier: .gregorian).dateComponents(in: .current, from: d)
        return String(format: "%04d-%02d-%02d", c.year ?? 0, c.month ?? 0, c.day ?? 0)
    }

    private static func prune(_ w: inout Workspace) {
        if w.days.count > keepDays {
            for k in w.days.keys.sorted().prefix(w.days.count - keepDays) {
                w.days[k] = nil; w.reportedDays[k] = nil
            }
        }
        if w.commands.count > keepCommands {
            for k in w.commands.sorted(by: { $0.value.savedBytes < $1.value.savedBytes })
                .prefix(w.commands.count - keepCommands).map(\.key) {
                w.commands[k] = nil
            }
        }
        if w.conversations.count > keepConversations {
            // No dates per conversation: keep the ones that saved the most.
            for k in w.conversations.sorted(by: { $0.value.rawBytes < $1.value.rawBytes })
                .prefix(w.conversations.count - keepConversations).map(\.key) {
                w.conversations[k] = nil
            }
        }
    }

    private func scheduleSaveLocked() {
        dirty = true
        guard file != nil, !saveScheduled else { return }
        saveScheduled = true
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 2) { [weak self] in self?.flush() }
    }

    /// Write now (tests, app termination).
    func flush() {
        lock.lock()
        saveScheduled = false
        guard dirty, let file else { lock.unlock(); return }
        dirty = false
        let data = try? JSONEncoder().encode(state)
        lock.unlock()
        guard let data else { return }
        try? FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? data.write(to: file, options: .atomic)
    }
}

/// Where a cloud uploader will plug in: given a report, send it and say
/// whether it went (a report that didn't go is reported again next time).
/// The app calls `sendPending` every few minutes; with no sink set (today:
/// the bromure.io side doesn't take these yet) nothing leaves the Mac.
/// When it does, the sink sends `events(report)` — one `tokens.squelch`
/// event per workspace and day, in the cloud events' shape — through the
/// enrolled install's uploader, outside the Security Timeline (savings
/// aren't a security decision) and skipping private workspaces.
enum SquelchCloud {
    nonisolated(unsafe) static var sink: (@Sendable (SquelchLedger.CloudReport) async -> Bool)?

    static let eventType = "tokens.squelch"

    /// The report as cloud events: (workspace, type, data).
    static func events(_ report: SquelchLedger.CloudReport) -> [(profileID: UUID, eventType: String, data: [String: AnyJSON])] {
        report.rows.compactMap { r in
            guard let id = UUID(uuidString: r.workspaceID) else { return nil }
            return (id, eventType, [
                "day": .string(r.day),
                "outputs": .int(r.outputs),
                "trimmed": .int(r.trimmed),
                "raw_tokens": .int(r.rawTokens),
                "kept_tokens": .int(r.keptTokens),
                "saved_tokens": .int(r.savedTokens),
                "estimate": .string("bytes/4"),
            ])
        }
    }

    /// Send what's pending, if an uploader is set.
    static func sendPending(_ ledger: SquelchLedger = .shared) async {
        guard let sink else { return }
        let report = ledger.pendingCloudReport()
        guard !report.isEmpty else { return }
        if await sink(report) { ledger.markReported(report) }
    }
}

/// One refresh in flight at a time (`ACAppDelegate.observeSquelchLedger`).
final class SquelchRefreshGate: @unchecked Sendable {
    private let lock = NSLock()
    private var busy = false
    func claim() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if busy { return false }
        busy = true
        return true
    }
    func release() { lock.lock(); busy = false; lock.unlock() }
}
