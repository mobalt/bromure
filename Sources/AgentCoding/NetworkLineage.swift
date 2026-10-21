import Foundation

/// Explains each network flow out of a workspace, end to end
/// (NETWORK_LINEAGE.md): the agent's tool call and the reasoning behind it,
/// the processes that ran (from the kernel sentry's `exec`), the flow (the
/// sentry's `net_flow`), and the decision the host made about it (the switch's
/// firewall, the MITM's L7 policy, or none for ICMP).
///
/// The tool call arrives first (the AI proxy sees the model's response before
/// the agent runs the command), so a shell the agent starts is linked the
/// moment its `exec` arrives, and every flow below it inherits the link.
public final class NetworkLineage: @unchecked Sendable {
    public static let shared = NetworkLineage()

    public struct ToolCall: Sendable {
        public var id: String
        public var tool: String
        public var command: String?
        public var reasoning: String
        public var at: Date
        /// From the agent's hook: the agent process, and which agent.
        public var agentPid: Int? = nil
        public var agent: String? = nil
    }

    struct ProcKey: Hashable { var pid: Int; var startNs: UInt64 }
    struct Proc {
        var key: ProcKey
        var ppid: Int
        /// The parent at exec, exactly: the frame's `chain[0]` (pid AND start
        /// time). A pid is reused within minutes, so `ppid` alone can name a
        /// later process. nil = an older sentry that sent no chain.
        var parent: ProcKey? = nil
        var comm: String
        var exe: String
        var argv: String
        var at: Date
        var link: (toolUseID: String, confidence: String)?
    }

    struct Decision { var action: String; var layer: String; var reason: String?; var host: String?; var at: Date }

    private struct VM {
        var procs: [ProcKey: Proc] = [:]
        /// Latest start per pid: a flow's leaf, and the parent of a process
        /// whose exec carried no chain.
        var byPid: [Int: ProcKey] = [:]
        var toolCalls: [ToolCall] = []
        var decisions: [String: Decision] = [:]       // "proto|dst|dport"
        var folded: [String: (first: Date, count: Int, data: [String: AnyJSON])] = [:]
        /// Guest client port → the proxied target (cooperative proxy).
        var proxied: [Int: (host: String, port: Int, at: Date)] = [:]
        /// Client ports claimed for two different targets, or by two
        /// connections: neither is believed (see `noteProxied`).
        var contested: [Int: Date] = [:]
        /// Connections that opened with a preamble naming each client port.
        var claimants: [Int: (count: Int, at: Date)] = [:]
    }

    private let lock = NSLock()
    private var vms: [UUID: VM] = [:]
    /// How long a tool call waits for its shell, a decision is remembered, and
    /// identical flows fold into one row.
    static let toolCallTTL: TimeInterval = 600
    static let shellWindow: TimeInterval = 30
    static let decisionTTL: TimeInterval = 60
    static let foldWindow: TimeInterval = 60
    static let maxProcs = 4096
    /// How long a flow waits for the switch's decision before it's emitted.
    var decisionWait: TimeInterval = 1.5
    /// Where events go (tests replace it).
    var emit: @Sendable (UUID, String, [String: AnyJSON]) -> Void = { pid, type, data in
        BACEventEmitter.shared.emitDetached(profileID: pid, eventType: type, eventData: data)
    }
    var now: @Sendable () -> Date = { Date() }

    // MARK: Inputs

    /// A tool call the AI proxy saw in a model response. Returns false when
    /// it was already known (a retried or replayed response), so its
    /// reasoning is reported once.
    /// The same call can arrive twice: from the agent's hook (before it runs,
    /// with the agent's pid) and from the AI proxy (with the reasoning). The
    /// second fills in what the first lacked; only the first returns true.
    @discardableResult
    public func noteToolCall(profileID: UUID, id: String, tool: String, command: String?, reasoning: String,
                             agentPid: Int? = nil, agent: String? = nil) -> Bool {
        lock.lock(); defer { lock.unlock() }
        var vm = vms[profileID] ?? VM()
        let t = now()
        if let i = vm.toolCalls.firstIndex(where: { $0.id == id && t.timeIntervalSince($0.at) <= Self.toolCallTTL }) {
            if vm.toolCalls[i].reasoning.isEmpty { vm.toolCalls[i].reasoning = reasoning }
            if vm.toolCalls[i].command == nil { vm.toolCalls[i].command = command }
            if vm.toolCalls[i].agentPid == nil { vm.toolCalls[i].agentPid = agentPid }
            if vm.toolCalls[i].agent == nil { vm.toolCalls[i].agent = agent }
            vms[profileID] = vm
            return false
        }
        vm.toolCalls.removeAll { t.timeIntervalSince($0.at) > Self.toolCallTTL || $0.id == id }
        vm.toolCalls.append(ToolCall(id: id, tool: tool, command: command, reasoning: reasoning, at: t,
                                     agentPid: agentPid, agent: agent))
        vms[profileID] = vm
        return true
    }

    /// The tool call behind `id`, while it's remembered.
    public func toolCall(profileID: UUID, id: String) -> ToolCall? {
        lock.lock(); defer { lock.unlock() }
        return vms[profileID]?.toolCalls.first { $0.id == id }
    }

    /// A sentry `exec` frame: remember the process, and link it to the tool
    /// call whose command it runs.
    public func noteExec(profileID: UUID, _ f: [String: Any]) {
        guard let pid = f["pid"] as? Int else { return }
        let key = ProcKey(pid: pid, startNs: Self.u64(f["start_ns"]))
        let t = now()
        lock.lock(); defer { lock.unlock() }
        var vm = vms[profileID] ?? VM()
        var p = Proc(key: key, ppid: f["ppid"] as? Int ?? 0, comm: f["comm"] as? String ?? "?",
                     exe: f["path"] as? String ?? "", argv: f["argv"] as? String ?? "", at: t, link: nil)
        if let first = (f["chain"] as? [[String: Any]])?.first, let pp = first["pid"] as? Int, pp == p.ppid {
            p.parent = ProcKey(pid: pp, startNs: Self.u64(first["start_ns"]))
        }
        p.link = Self.matchToolCall(argv: p.argv, calls: vm.toolCalls, at: t)
        if p.link == nil {
            // The agent's hook named its own pid: a process it starts right
            // after a tool call is that call's, even when the agent wrapped the
            // command beyond recognition. Each call links one such process.
            let taken = Set(vm.procs.values.compactMap { $0.link?.toolUseID })
            if let c = vm.toolCalls.reversed().first(where: {
                $0.agentPid == p.ppid && !taken.contains($0.id) && t.timeIntervalSince($0.at) <= 10
            }) { p.link = (c.id, "fuzzy") }
        }
        vm.procs[key] = p
        vm.byPid[pid] = key
        if vm.procs.count > Self.maxProcs {
            // Oldest first; a long-lived agent keeps being re-seen in chains.
            let drop = vm.procs.values.sorted { $0.at < $1.at }.prefix(vm.procs.count - Self.maxProcs * 3 / 4)
            for d in drop { vm.procs[d.key] = nil; if vm.byPid[d.key.pid] == d.key { vm.byPid[d.key.pid] = nil } }
        }
        vms[profileID] = vm
    }

    /// A request that arrived through the guest's proxy bridge, from the
    /// guest client port `sport` (the bridge's `BROMURE-CLIENT` preamble).
    ///
    /// The line comes from the guest, and any process there that can open
    /// vsock could send one (agentd's bridge isn't authenticated to the
    /// host), so a claim is held to what it can honestly mean. It only
    /// relabels a loopback flow to the bridge itself (see `resolve`), and a
    /// port claimed for two different targets is contested: neither claim
    /// is believed, whichever came first. The bridge always sends the real
    /// line for a connection that went through it, so a forged line for
    /// that connection can only ever make its row stay "127.0.0.1:<bridge>"
    /// — never name another host.
    public func noteProxied(profileID: UUID, sport: Int, host: String, port: Int) {
        lock.lock(); defer { lock.unlock() }
        var vm = vms[profileID] ?? VM()
        let t = now()
        vm.proxied = vm.proxied.filter { t.timeIntervalSince($0.value.at) < 120 }
        vm.contested = vm.contested.filter { t.timeIntervalSince($0.value) < 120 }
        if vm.contested[sport] != nil {
            vm.contested[sport] = t
        } else if let held = vm.proxied[sport], held.host != host || held.port != port {
            vm.proxied[sport] = nil
            vm.contested[sport] = t
        } else {
            vm.proxied[sport] = (host, port, t)
        }
        vms[profileID] = vm
    }

    /// A connection to the MITM opened with a preamble naming `sport` — called
    /// as soon as its first line arrives, before the request is read. agentd
    /// writes that line the moment it accepts the client, so a connection
    /// through the bridge registers here at once; a second connection naming
    /// the same port (a forged line, however early or however long its
    /// request is held back) contests the port before the flow is resolved.
    public func noteClaimant(profileID: UUID, sport: Int) {
        lock.lock(); defer { lock.unlock() }
        var vm = vms[profileID] ?? VM()
        let t = now()
        vm.claimants = vm.claimants.filter { t.timeIntervalSince($0.value.at) < 120 }
        vm.contested = vm.contested.filter { t.timeIntervalSince($0.value) < 120 }
        let n = (vm.claimants[sport]?.count ?? 0) + 1
        vm.claimants[sport] = (n, t)
        if n > 1 { vm.contested[sport] = t; vm.proxied[sport] = nil }
        vms[profileID] = vm
    }

    /// The guest proxy bridge's loopback ports (agentd's listener): 65534,
    /// or 8080 on a workspace resumed from an older daemon's snapshot.
    static let bridgePorts: Set<Int> = [SessionDisk.guestProxyPort, 8080]

    /// The host's decision about a flow (switch L4, MITM L7, binary identity).
    public func noteDecision(profileID: UUID, proto: String, dst: String, dport: Int,
                             action: String, layer: String, reason: String? = nil, host: String? = nil) {
        lock.lock(); defer { lock.unlock() }
        var vm = vms[profileID] ?? VM()
        let t = now()
        vm.decisions = vm.decisions.filter { t.timeIntervalSince($0.value.at) < Self.decisionTTL }
        let key = "\(proto)|\(dst)|\(dport)"
        // A deny outranks an allow for the same destination (the L7 layer can
        // refuse what L4 let through).
        if let old = vm.decisions[key], old.action == "deny", action != "deny", t.timeIntervalSince(old.at) < 5 { }
        else { vm.decisions[key] = Decision(action: action, layer: layer, reason: reason, host: host, at: t) }
        vms[profileID] = vm
    }

    /// A sentry `net_flow` frame: resolve the process chain and the tool call
    /// now, wait briefly for the host's decision, then emit `net.flow`.
    public func noteFlow(profileID: UUID, _ f: [String: Any]) {
        guard let pid = f["pid"] as? Int else { return }
        let proto = f["proto"] as? String ?? "ip"
        let dst = f["dst"] as? String ?? "?"
        let dport = f["dport"] as? Int ?? 0
        let leaf = ProcKey(pid: pid, startNs: Self.u64(f["start_ns"]))
        let snapshot = lineage(profileID: profileID, leaf: leaf, frame: f)
        // Nearest first: the policy note goes to the agent whose tree this is.
        PolicySteering.shared.noteFlow(profileID: profileID, dst: dst, dport: dport,
                                       pids: snapshot.processes.reversed().compactMap {
                                           if case .int(let p)? = $0["pid"] { return p }; return nil })
        let flowID = UUID().uuidString
        DispatchQueue.global().asyncAfter(deadline: .now() + decisionWait) { [weak self] in
            self?.resolve(profileID: profileID, flowID: flowID, frame: f, proto: proto, dst: dst,
                          dport: dport, processes: snapshot.processes, link: snapshot.link)
        }
    }

    // MARK: Join

    private func lineage(profileID: UUID, leaf: ProcKey, frame f: [String: Any])
        -> (processes: [[String: AnyJSON]], link: (call: ToolCall, confidence: String)?) {
        lock.lock(); defer { lock.unlock() }
        let vm = vms[profileID] ?? VM()
        var chain: [Proc] = []
        var cursor: ProcKey? = vm.procs[leaf] != nil ? leaf : (leaf.startNs == 0 ? vm.byPid[leaf.pid] : nil)
        var seen = Set<ProcKey>()
        while let k = cursor, let p = vm.procs[k], seen.insert(k).inserted, chain.count < 16 {
            chain.append(p)
            cursor = Self.parentKey(of: p, in: vm)
        }
        // Processes the host never saw exec (older than the sentry): the
        // frame's own chain, nearest first.
        if chain.isEmpty {
            chain.append(Proc(key: leaf, ppid: 0, comm: f["comm"] as? String ?? "?",
                              exe: f["path"] as? String ?? "", argv: "", at: now(), link: nil))
        }
        // The kernel's chain for this flow (nearest first, by pid and start
        // time) picks up where the walk ends: after the walk's last process,
        // or its exact parent. All of it when the walk knew only the leaf.
        if let frameChain = f["chain"] as? [[String: Any]] {
            let keys: [ProcKey] = frameChain.compactMap { c in
                (c["pid"] as? Int).map { ProcKey(pid: $0, startNs: Self.u64(c["start_ns"])) }
            }
            let last = chain.last!
            let from: Int? = {
                if let i = keys.firstIndex(of: last.key) { return i + 1 }
                if let parent = last.parent, let i = keys.firstIndex(of: parent) { return i }
                return chain.count == 1 ? 0 : nil
            }()
            if let from {
                for (i, c) in frameChain.enumerated() where i >= from && i < keys.count {
                    let k = keys[i]
                    guard !seen.contains(k), chain.count < 16 else { continue }
                    seen.insert(k)
                    chain.append(vm.procs[k] ?? Proc(key: k, ppid: 0, comm: c["comm"] as? String ?? "?",
                                                     exe: "", argv: "", at: now(), link: nil))
                }
            }
        }
        var link: (ToolCall, String)?
        for p in chain {
            if let l = p.link, let call = vm.toolCalls.first(where: { $0.id == l.toolUseID }) { link = (call, l.confidence); break }
        }
        // Root → leaf, the 8 nearest the flow (the viewer's cap).
        let processes: [[String: AnyJSON]] = chain.prefix(8).reversed().map { p in
            var d: [String: AnyJSON] = ["pid": .int(p.key.pid), "comm": .string(p.comm)]
            if p.key.startNs != 0 { d["start_ns"] = .int(Int(truncatingIfNeeded: p.key.startNs)) }
            if !p.exe.isEmpty { d["exe"] = .string(p.exe) }
            if !p.argv.isEmpty { d["argv"] = .string(String(p.argv.prefix(256))) }
            return d
        }
        return (processes, link)
    }

    /// The process that started `p`: the exact identity its exec recorded,
    /// else (an older sentry) the latest process with its ppid, but only one
    /// that started before `p` — a pid reused afterwards isn't its parent.
    private static func parentKey(of p: Proc, in vm: VM) -> ProcKey? {
        if let parent = p.parent { return parent }
        guard p.ppid != 0, let k = vm.byPid[p.ppid] else { return nil }
        if k.startNs != 0, p.key.startNs != 0, k.startNs > p.key.startNs { return nil }
        return k
    }

    private func resolve(profileID: UUID, flowID: String, frame f: [String: Any], proto: String, dst: String,
                         dport: Int, processes: [[String: AnyJSON]], link: (call: ToolCall, confidence: String)?) {
        let t = now()
        lock.lock()
        var vm = vms[profileID] ?? VM()
        var dst = dst, dport = dport
        var viaProxy = false
        // A loopback connect to the guest's proxy bridge: the real destination
        // is the CONNECT target the bridge tagged with this client port.
        // Only a flow to the bridge itself: a loopback connection anywhere
        // else is never relabelled by a (guest-written) claim.
        if dst.hasPrefix("127.") || dst == "::1", Self.bridgePorts.contains(dport),
           let sport = f["sport"] as? Int, let p = vm.proxied[sport] {
            dst = p.host; dport = p.port; viaProxy = true
        }
        var decision = viaProxy ? vm.decisions["\(proto)|host:\(dst)|\(dport)"] : vm.decisions["\(proto)|\(dst)|\(dport)"]
        // The MITM decides by hostname (L7): a deny or audit there overrides
        // the switch's allow for the same flow.
        if let host = decision?.host, let l7 = vm.decisions["\(proto)|host:\(host)|\(dport)"],
           l7.action != "allow", decision?.action != "deny" {
            decision = Decision(action: l7.action, layer: l7.layer, reason: l7.reason, host: host, at: l7.at)
        }
        let leafExe = processes.last.flatMap { if case .string(let s)? = $0["exe"] { return s } else { return nil } } ?? "?"
        let foldKey = "\(leafExe)|\(proto)|\(dst)|\(dport)"
        var data: [String: AnyJSON] = [
            "flow_id": .string(flowID), "proto": .string(proto), "dst": .string(dst), "dport": .int(dport),
            "count": .int(max(1, f["count"] as? Int ?? 1)), "processes": .array(processes.map { .object($0) }),
        ]
        if let sport = f["sport"] as? Int { data["sport"] = .int(sport) }
        if viaProxy {
            data["via_proxy"] = .bool(true)
            data["host"] = .string(dst)
            // No explicit decision for a proxied target = the proxy let it
            // through (a refusal is always logged).
            if decision == nil { decision = Decision(action: "allow", layer: "proxy", reason: nil, host: dst, at: t) }
        }
        if let host = decision?.host { data["host"] = .string(host) }
        if let d = decision {
            data["decision"] = .string(d.action == "deny" ? "deny" : d.action == "audit" ? "audit" : "allow")
            data["layer"] = .string(d.layer)
            if let r = d.reason { data["reason"] = .string(r) }
        } else {
            // The switch filters TCP and UDP only; anything else passes untouched.
            data["decision"] = .string(proto == "tcp" || proto == "udp" ? "unknown" : "unfiltered")
        }
        if let link {
            data["agent"] = .object(["tool": .string(link.call.tool), "tool_use_id": .string(String(link.call.id.prefix(128))),
                                     "confidence": .string(link.confidence)])
            if let c = link.call.command { data["command"] = .string(String(c.prefix(256))) }
        }
        // Fold identical flows from the same program for a minute.
        vm.folded = vm.folded.filter { t.timeIntervalSince($0.value.first) < Self.foldWindow || $0.value.count > 0 }
        var flush: [[String: AnyJSON]] = []
        for (k, v) in vm.folded where t.timeIntervalSince(v.first) >= Self.foldWindow {
            if v.count > 0 {
                var d = v.data
                d["count"] = .int(v.count); d["repeat"] = .bool(true)
                d["flow_id"] = .string(UUID().uuidString)   // one id per uploaded event
                flush.append(d)
            }
            vm.folded[k] = nil
        }
        let isRepeat = vm.folded[foldKey] != nil
        if isRepeat { vm.folded[foldKey]!.count += max(1, f["count"] as? Int ?? 1); vm.folded[foldKey]!.data = data }
        else { vm.folded[foldKey] = (t, 0, data) }
        vms[profileID] = vm
        lock.unlock()
        for d in flush { emit(profileID, "net.flow", d) }
        if !isRepeat { emit(profileID, "net.flow", data) }
    }

    // MARK: Matching a shell to a tool call

    /// The tool call whose command this argv runs, within `shellWindow` of
    /// the response. Agents wrap commands (Claude Code: `bash -c -l '…
    /// eval '"'"'<cmd>'"'"' …'`), so both sides are compared with quoting and
    /// whitespace removed.
    static func matchToolCall(argv: String, calls: [ToolCall], at: Date) -> (toolUseID: String, confidence: String)? {
        guard !argv.isEmpty else { return nil }
        let a = normalize(argv)
        let recent = calls.filter { at.timeIntervalSince($0.at) <= shellWindow && $0.command != nil }
        // Newest first: an agent re-running a command means the latest call.
        for c in recent.reversed() {
            let n = normalize(c.command!)
            if n.count >= 2, a.contains(n) { return (c.id, "exact") }
        }
        return nil
    }

    static func normalize(_ s: String) -> String {
        String(s.unicodeScalars.filter { !"'\"\\ \t\n".unicodeScalars.contains($0) }.map(Character.init))
    }

    static func u64(_ v: Any?) -> UInt64 {
        if let n = v as? NSNumber { return n.uint64Value }
        if let s = v as? String { return UInt64(s) ?? 0 }
        return 0
    }

    func reset(profileID: UUID) { lock.lock(); vms[profileID] = nil; lock.unlock() }
}
