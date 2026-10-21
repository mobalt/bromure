import Foundation
import SandboxEngine

/// Tells an agent, in its own session, when the workspace's policy blocked
/// something it tried: "this was refused by policy (why); don't route around
/// it, ask the user". An agent that only sees ECONNRESET or EACCES takes the
/// block for a fault and tries another host, port, tool or path — which reads
/// as an agent going rogue. A 403 body already explains itself; an L4 reset,
/// an SNI close or a sandbox EACCES doesn't.
///
/// Inputs come from the event emitter (every denial passes through it), the
/// kernel sentry (sandbox denials, with the process chain) and the network
/// lineage (which process opened a flow). A denial is attributed to the agent
/// tab whose process tree it came from — known from the agents' PreToolUse
/// hooks, which report the agent's pid and window — or, failing that, given
/// to every agent in the workspace. Delivery is the app's (`deliver`): a note
/// Claude's hook hands the model mid-turn, or a typed line once a tab is idle.
public final class PolicySteering: @unchecked Sendable {
    public static let shared = PolicySteering()

    /// Whether a workspace tells its agents (`Profile.tellsAgentOnDeny`).
    var enabledProvider: @Sendable (UUID) -> Bool = { _ in false }
    /// The workspace's OpenShell policy, to name the rule and its reason.
    var openShellProvider: @Sendable (UUID) -> OpenShellPolicy? = { _ in nil }
    /// Whether agents may propose rules at `policy.local`.
    var advisorOnProvider: @Sendable (UUID) -> Bool = { _ in false }
    /// Hand one note to the agent in `window`; nil = every agent in the
    /// workspace, or only a sole agent when `soleOnly` (a denial that can't be
    /// pinned on anyone and is too common to tell everyone about).
    var deliver: @Sendable (_ profileID: UUID, _ window: Int?, _ text: String, _ soleOnly: Bool) -> Void = { _, _, _, _ in }
    var now: @Sendable () -> Date = { Date() }

    /// How long a connection-level denial waits for the process that opened
    /// the flow, when several agents could have: the sentry reports flows in
    /// batches, measured ~10 s after the connect. With one agent there is no
    /// question whose it was, and the note goes at once.
    var attributionWait: TimeInterval = 15.0
    /// The same denial is told to the same tab once in this window.
    static let repeatWindow: TimeInterval = 300
    /// At most this many notes per tab a minute: a loop probing paths gets
    /// told a few times, not drowned.
    static let burst = 5
    static let notePrefix = "[Bromure policy]"
    /// An agent process's own connection (no tool in it) counts as its
    /// background traffic when it made no tool call for this long.
    static let toolQuiet: TimeInterval = 30
    /// Where agents send their own telemetry, error reports and feature
    /// flags. A block there is nothing the agent chose: telling it to "stop
    /// and ask the user" about its own telemetry only confuses it.
    static let backgroundHostSuffixes = [
        "datadoghq.com", "datadoghq.eu", "statsig.com", "statsigapi.net", "featuregates.org",
        "featureassets.org", "prodregistryv2.org", "sentry.io", "segment.io", "posthog.com",
        "honeycomb.io",
    ]

    private struct Flow { var pids: [Int]; var at: Date }
    private struct Pending { var profileID: UUID; var keys: [String]; var host: String?; var dedupe: String; var text: String }

    private let lock = NSLock()
    /// Agent pid → its tmux window, per workspace (from the PreToolUse hooks).
    private var agents: [UUID: [Int: (window: Int, at: Date)]] = [:]
    /// Recent flows per workspace: "dst|dport" → the process chain's pids.
    private var flows: [UUID: [String: Flow]] = [:]
    private var pending: [UUID: Pending] = [:]
    private var sent: [String: Date] = [:]
    private var recent: [String: [Date]] = [:]

    // MARK: Inputs

    /// An agent's PreToolUse hook: the agent process in tmux window `window`.
    public func noteAgent(profileID: UUID, pid: Int, window: Int) {
        lock.lock(); defer { lock.unlock() }
        var m = agents[profileID] ?? [:]
        let t = now()
        // A window's agent restarted: its old pid no longer speaks for it.
        m = m.filter { $0.value.window != window || $0.key == pid }
        m[pid] = (window, t)
        if m.count > 64 { m = m.filter { t.timeIntervalSince($0.value.at) < 3600 } }
        agents[profileID] = m
    }

    /// The sentry's `net_flow`: which processes opened a flow to `dst:dport`
    /// (nearest first). Claims a denial waiting for it.
    public func noteFlow(profileID: UUID, dst: String, dport: Int, pids: [Int]) {
        guard enabledProvider(profileID) else { return }
        let key = "\(dst)|\(dport)"
        lock.lock()
        let t = now()
        var f = (flows[profileID] ?? [:]).filter { t.timeIntervalSince($0.value.at) < 10 }
        f[key] = Flow(pids: pids, at: t)
        flows[profileID] = f
        var claimed: Pending?
        for (id, p) in pending where p.profileID == profileID && p.keys.contains(key) {
            claimed = p; pending[id] = nil; break
        }
        let window = windowLocked(profileID, pids)
        let background = claimed.map { backgroundLocked(profileID, pids, host: $0.host) } ?? false
        lock.unlock()
        if let claimed {
            Self.log("\(claimed.dedupe): flow \(pids.prefix(4)) → \(background ? "agent's own traffic, not told" : "window \(window.map(String.init) ?? "none")")")
        }
        if let claimed, !background { send(claimed.profileID, window, claimed.dedupe, claimed.text, soleOnly: window == nil) }
    }

    /// Firewall layers that deny inside a request (the MITM's L7 rules, web
    /// filtering): no single flow to attribute, so every agent is told.
    static let requestLevelLayers: Set<String> = ["l7", "web"]

    /// Every event the emitter sees; acts on policy denials.
    public func observe(profileID: UUID, eventType: String, eventData d: [String: AnyJSON]) {
        if eventType == "net.flow" { noteLineage(profileID: profileID, d); return }
        guard eventType == "egress.firewall" || eventType == "guardrails.block",
              enabledProvider(profileID) else { return }
        func s(_ k: String) -> String? { if case .string(let v)? = d[k], !v.isEmpty { return v }; return nil }
        var port = 0
        if case .int(let p)? = d["port"] { port = p }
        if eventType == "guardrails.block" {
            let what = "\(s("method") ?? "a request to") \(s("host") ?? "?")\(s("path").map(Self.shortPath) ?? "")"
            let text = Self.message(what: what, why: s("reason") ?? "a workspace guardrail", kind: "guardrails",
                                    advisor: false)
            send(profileID, nil, "guard|\(s("host") ?? "")|\(s("reason") ?? "")", text, soleOnly: false)
            return
        }
        guard s("action") == "deny" else { return }
        if case .bool(true)? = d["closed"] { return }   // a cut of a flow already told about
        let layer = s("layer") ?? "l4"
        let host = s("host"), ip = s("ip") ?? s("dst_ip")
        let target = host ?? ip ?? "?"
        let why = reason(profileID: profileID, layer: layer, host: host, ip: ip, port: port,
                         rule: s("rule"), reason: s("reason"))
        let what: String
        if let method = s("method") {
            what = "\(method == "WEBSOCKET_TEXT" ? "a WebSocket message to" : method) \(target)\(s("path").map(Self.shortPath) ?? "")"
        } else if s("proto") == "udp" || s("proto") == "quic" {
            what = "UDP to \(target):\(port)"
        } else {
            what = "connecting to \(target):\(port)"
        }
        let text = Self.message(what: what, why: why, kind: "network",
                                advisor: advisorOnProvider(profileID) && openShellProvider(profileID) != nil)
        let dedupe = "net|\(target)|\(port)|\(s("method") ?? "")"
        // Connection-level denials (no request yet) — the switch's l4/sni,
        // container traffic, the cooperative proxy's CONNECT check, binary
        // identity — wait for the flow the sentry saw, which names the
        // process (through the proxy bridge too: `host:<name>|<port>`). Only
        // a request-level deny, made inside a request the proxy can't tie to
        // one flow, is told at once.
        guard !Self.requestLevelLayers.contains(layer) else {
            send(profileID, nil, dedupe, text, soleOnly: false)
            return
        }
        var keys: [String] = []
        if let ip { keys.append("\(ip)|\(port)") }
        if let host { keys.append("\(host)|\(port)"); keys.append("host:\(host)|\(port)") }
        lock.lock()
        let t = now()
        let seen = keys.lazy.compactMap { self.flows[profileID]?[$0] }.first { t.timeIntervalSince($0.at) < 5 }
        if let seen {
            let window = windowLocked(profileID, seen.pids)
            let background = backgroundLocked(profileID, seen.pids, host: host)
            lock.unlock()
            Self.log("\(dedupe): flow \(seen.pids.prefix(4)) → \(background ? "agent's own traffic, not told" : "window \(window.map(String.init) ?? "none")")")
            // A process under no agent's tab: only a sole agent is told.
            if !background { send(profileID, window, dedupe, text, soleOnly: window == nil) }
            return
        }
        // One agent (or none known): no one else it could be — don't wait.
        let windows = Set((agents[profileID] ?? [:]).values.filter { t.timeIntervalSince($0.at) < 3600 }.map(\.window))
        if windows.count <= 1 {
            lock.unlock()
            if Self.isBackgroundHost(host) { Self.log("\(dedupe): agent telemetry, not told"); return }
            Self.log("\(dedupe): \(windows.isEmpty ? "no agent known" : "the only agent") → window \(windows.first.map(String.init) ?? "every agent")")
            send(profileID, windows.first, dedupe, text, soleOnly: false)
            return
        }
        let id = UUID()
        pending[id] = Pending(profileID: profileID, keys: keys, host: host, dedupe: dedupe, text: text)
        lock.unlock()
        Self.log("\(dedupe): waiting for its flow \(keys)")
        DispatchQueue.global().asyncAfter(deadline: .now() + attributionWait) { [weak self] in
            guard let self else { return }
            self.lock.lock()
            let p = self.pending.removeValue(forKey: id)
            self.lock.unlock()
            if let p { Self.log("\(p.dedupe): no flow named a process\(Self.isBackgroundHost(p.host) ? "; agent telemetry, not told" : "")") }
            // Nobody to pin it on: an agent's telemetry isn't worth telling
            // every agent about.
            if let p, !Self.isBackgroundHost(p.host) { self.send(p.profileID, nil, p.dedupe, p.text, soleOnly: false) }
        }
    }

    /// NetworkLineage's `net.flow`: a denied flow with its process chain
    /// (root → leaf) and real target — through the proxy bridge too.
    private func noteLineage(profileID: UUID, _ d: [String: AnyJSON]) {
        guard case .string("deny")? = d["decision"], enabledProvider(profileID),
              case .array(let procs)? = d["processes"], case .int(let port)? = d["dport"] else { return }
        let pids: [Int] = procs.reversed().compactMap {
            if case .object(let o) = $0, case .int(let p)? = o["pid"] { return p }; return nil }
        guard !pids.isEmpty else { return }
        var target = "?"
        if case .string(let h)? = d["host"] { target = h } else if case .string(let h)? = d["dst"] { target = h }
        Self.log("denied flow to \(target):\(port) from \(pids.prefix(4))")
        if case .string(let dst)? = d["dst"] { noteFlow(profileID: profileID, dst: dst, dport: port, pids: pids) }
        if case .string(let host)? = d["host"] { noteFlow(profileID: profileID, dst: "host:\(host)", dport: port, pids: pids) }
    }

    /// A sandbox denial from the kernel sentry (the raw frame, chain and all).
    public func noteSandboxDenial(profileID: UUID, frame f: [String: Any]) {
        guard enabledProvider(profileID), (f["phase"] as? String ?? "session") == "session",
              (f["sandboxed"] as? Bool) != false else { return }
        var pids: [Int] = []
        if let p = f["pid"] as? Int { pids.append(p) }
        if let pp = f["ppid"] as? Int { pids.append(pp) }
        for c in f["chain"] as? [[String: Any]] ?? [] { if let p = c["pid"] as? Int { pids.append(p) } }
        let comm = f["comm"] as? String ?? "a process"
        let kind = f["kind"] as? String ?? ""
        let what: String
        let dedupe: String
        if kind == "seccomp_denied" {
            let nr = (f["syscall"] as? NSNumber)?.intValue ?? -1
            what = "\(comm) making system call \(Self.syscallName(nr).map { "\($0) (#\(nr))" } ?? "#\(nr)")"
            dedupe = "sys|\(nr)"
        } else {
            let path = f["path"] as? String ?? "?"
            let op = (f["op"] as? String).map(Self.opWord) ?? "accessing"
            what = "\(comm) \(op) \(path)"
            dedupe = "fs|\(f["op"] as? String ?? "")|\((path as NSString).deletingLastPathComponent)"
        }
        let text = Self.message(what: what, why: kind == "seccomp_denied" ? "the system call filter" : "the filesystem policy",
                                kind: "sandbox", advisor: false)
        lock.lock()
        let window = windowLocked(profileID, pids)
        lock.unlock()
        // Unattributed: likely the user's own shell or a helper, and file
        // denials are common — tell a sole agent, never everyone.
        send(profileID, window, dedupe, text, soleOnly: window == nil)
    }

    func reset(profileID: UUID) {
        lock.lock(); defer { lock.unlock() }
        agents[profileID] = nil; flows[profileID] = nil
        sent = sent.filter { !$0.key.hasPrefix(profileID.uuidString) }
    }

    // MARK: Composing

    /// The reason to quote: the event's own, the pf rule, or what the
    /// OpenShell policy says about this destination (the switch and the SNI
    /// layer don't carry it).
    func reason(profileID: UUID, layer: String, host: String?, ip: String?, port: Int,
                rule: String?, reason: String?) -> String {
        let os = openShellProvider(profileID)
        var named: String?
        if let rule, let r = os?.networkPolicies.first(where: { $0.key == rule }) {
            named = r.name == r.key ? "rule `\(r.key)`" : "rule `\(r.key)` (\(r.name))"
        }
        if let reason { return named.map { "\($0): \(reason)" } ?? reason }
        if let os, port > 0, port <= 65_535 {
            let addr = ip.flatMap { EgressPolicy.parseIPv4Address($0) }
            if case .deny(let r) = os.evaluateConnect(hostnames: host.map { [$0] } ?? [], ip: addr,
                                                      port: UInt16(port)) {
                // The address is checked last, so its "no policy" reason wins;
                // the name is what the agent asked for.
                if let host, r.hasPrefix("no network policy allows ") {
                    return "no network policy allows \(host):\(port)"
                }
                return r
            }
        }
        if let rule { return "firewall rule `\(rule)`" }
        return "the workspace's firewall denies what no rule allows"
    }

    static func message(what: String, why: String, kind: String, advisor: Bool) -> String {
        let scope = kind == "sandbox" ? "sandbox" : kind == "guardrails" ? "guardrails" : "network policy"
        var m = "\(notePrefix) This workspace's \(scope) blocked \(what) — \(why). "
        m += "This is a deliberate restriction, not a fault: don't retry it or reach the same thing another way "
        m += kind == "sandbox" ? "(sudo, chmod, copies, other paths or tools); " : "(other hosts, addresses, ports, proxies or tools); "
        m += "that is blocked too and looks like evading the policy. If your task needs it, stop and tell the user what you need and why so they can decide."
        if advisor { m += " You may also propose the narrowest rule through http://policy.local (see http://policy.local/v1/guide)." }
        return m
    }

    static func shortPath(_ p: String) -> String {
        let bare = p.split(separator: "?", maxSplits: 1).first.map(String.init) ?? p
        return bare.count > 80 ? String(bare.prefix(80)) + "…" : bare
    }

    static func opWord(_ op: String) -> String {
        switch op {
        case "read", "open_read": return "reading"
        case "write", "open_write", "truncate": return "writing"
        case "exec", "execute": return "executing"
        case "create", "mknod", "mkdir": return "creating"
        case "unlink", "rmdir", "remove": return "deleting"
        case "rename", "link": return "renaming"
        default: return "\(op) on"
        }
    }

    /// arm64 numbers of the syscalls the sandbox's filter refuses.
    static func syscallName(_ nr: Int) -> String? {
        [40: "mount", 39: "umount2", 97: "unshare", 268: "setns", 280: "bpf", 117: "ptrace",
         104: "kexec_load", 294: "kexec_file_load", 105: "init_module", 273: "finit_module",
         106: "delete_module", 241: "perf_event_open", 41: "pivot_root", 51: "chroot",
         217: "add_key", 218: "request_key", 219: "keyctl", 142: "reboot", 167: "prctl"][nr]
    }

    // MARK: Sending

    /// Tabs whose agent's hooks reported in this past hour — agents the app
    /// may not list as sessions (one started from a shell).
    func agentWindows(profileID: UUID) -> Set<Int> {
        lock.lock(); defer { lock.unlock() }
        let t = now()
        return Set((agents[profileID] ?? [:]).values.filter { t.timeIntervalSince($0.at) < 3600 }.map(\.window))
    }

    static func log(_ s: String) {
        let t = String(format: "%.3f", Date().timeIntervalSince1970.truncatingRemainder(dividingBy: 1000))
        FileHandle.standardError.write(Data("[policy-steering] \(t) \(s)\n".utf8))
    }

    static func isBackgroundHost(_ host: String?) -> Bool {
        guard let h = host?.lowercased() else { return false }
        return backgroundHostSuffixes.contains { h == $0 || h.hasSuffix("." + $0) }
    }

    /// The agent process itself opened the flow (no tool process under it):
    /// its telemetry, or anything while it ran no tool. A tool it runs (curl,
    /// git) has its own pid; an in-process fetch tool (Claude's WebFetch)
    /// right after its PreToolUse still counts.
    private func backgroundLocked(_ profileID: UUID, _ pids: [Int], host: String?) -> Bool {
        guard let first = pids.first, let a = agents[profileID]?[first] else { return false }
        return Self.isBackgroundHost(host) || now().timeIntervalSince(a.at) > Self.toolQuiet
    }

    private func windowLocked(_ profileID: UUID, _ pids: [Int]) -> Int? {
        guard let m = agents[profileID] else { return nil }
        for p in pids { if let w = m[p]?.window { return w } }
        return nil
    }

    private func send(_ profileID: UUID, _ window: Int?, _ dedupe: String, _ text: String, soleOnly: Bool) {
        let t = now()
        let tab = window.map(String.init) ?? "*"
        let key = "\(profileID.uuidString)|\(tab)|\(dedupe)"
        let anyKey = "\(profileID.uuidString)|*|\(dedupe)"
        lock.lock()
        sent = sent.filter { t.timeIntervalSince($0.value) < Self.repeatWindow }
        // Told already — to this tab, or to every tab.
        if sent[key] != nil || sent[anyKey] != nil { lock.unlock(); return }
        let burstKey = "\(profileID.uuidString)|\(tab)"
        let lastMinute = (recent[burstKey] ?? []).filter { t.timeIntervalSince($0) < 60 }
        if lastMinute.count >= Self.burst { lock.unlock(); return }
        recent[burstKey] = lastMinute + [t]
        sent[key] = t
        lock.unlock()
        deliver(profileID, window, text, soleOnly)
    }
}
