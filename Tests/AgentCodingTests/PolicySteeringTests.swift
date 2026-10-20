import Foundation
import Testing
import SandboxEngine
@testable import bromure_ac

/// Collects the notes steering hands out.
final class SteeringSink: @unchecked Sendable {
    struct Note { var window: Int?; var text: String; var soleOnly: Bool }
    private let lock = NSLock()
    private var items: [Note] = []
    func add(_ n: Note) { lock.lock(); items.append(n); lock.unlock() }
    var notes: [Note] { lock.lock(); defer { lock.unlock() }; return items }
}

/// A clock a test moves by hand.
final class SteeringClock: @unchecked Sendable {
    private let lock = NSLock()
    private var t: Date
    init(_ t: Date) { self.t = t }
    var now: Date {
        get { lock.lock(); defer { lock.unlock() }; return t }
        set { lock.lock(); t = newValue; lock.unlock() }
    }
}

@Suite("Policy steering: a blocked action is explained to the agent that tried it")
struct PolicySteeringTests {
    static let ws = UUID()
    static let policy = try! OpenShellPolicy.parse("""
    version: 1
    network_policies:
      github:
        name: GitHub API
        endpoints:
          - host: api.github.com
            port: 443
    """)

    func steering(_ sink: SteeringSink, enabled: Bool = true, advisor: Bool = false) -> PolicySteering {
        let s = PolicySteering()
        s.enabledProvider = { _ in enabled }
        s.openShellProvider = { _ in Self.policy }
        s.advisorOnProvider = { _ in advisor }
        s.attributionWait = 0.05
        s.deliver = { _, window, text, sole in sink.add(.init(window: window, text: text, soleOnly: sole)) }
        return s
    }

    func l4Deny(host: String = "evil.example", ip: String = "203.0.113.9", port: Int = 443) -> [String: AnyJSON] {
        ["action": .string("deny"), "layer": .string("l4"), "proto": .string("tcp"),
         "host": .string(host), "ip": .string(ip), "port": .int(port)]
    }

    @Test("Off: nothing is told")
    func disabled() async throws {
        let sink = SteeringSink()
        let s = steering(sink, enabled: false)
        s.observe(profileID: Self.ws, eventType: "egress.firewall", eventData: l4Deny())
        try await Task.sleep(nanoseconds: 150_000_000)
        #expect(sink.notes.isEmpty)
    }

    @Test("A reset connection goes to the tab whose process opened it, with OpenShell's reason")
    func attributedByFlow() {
        let sink = SteeringSink()
        let s = steering(sink)
        s.noteAgent(profileID: Self.ws, pid: 500, window: 3)
        // curl (pid 900) under bash (pid 800) under the agent (pid 500).
        s.noteFlow(profileID: Self.ws, dst: "203.0.113.9", dport: 443, pids: [900, 800, 500])
        s.observe(profileID: Self.ws, eventType: "egress.firewall", eventData: l4Deny())
        #expect(sink.notes.count == 1)
        let n = sink.notes[0]
        #expect(n.window == 3)
        #expect(n.text.hasPrefix(PolicySteering.notePrefix))
        #expect(n.text.contains("connecting to evil.example:443"))
        #expect(n.text.contains("no network policy allows evil.example:443"))
        #expect(n.text.contains("tell the user"))
        #expect(!n.text.contains("policy.local"))
    }

    @Test("A flow reported just after the denial still claims it")
    func flowAfterDenial() async throws {
        let sink = SteeringSink()
        let s = steering(sink)
        s.attributionWait = 1
        s.noteAgent(profileID: Self.ws, pid: 500, window: 2)
        s.noteAgent(profileID: Self.ws, pid: 600, window: 5)   // two agents: it waits for the flow
        s.observe(profileID: Self.ws, eventType: "egress.firewall", eventData: l4Deny())
        #expect(sink.notes.isEmpty)
        s.noteFlow(profileID: Self.ws, dst: "203.0.113.9", dport: 443, pids: [901, 500])
        #expect(sink.notes.count == 1)
        #expect(sink.notes.first?.window == 2)
        try await Task.sleep(nanoseconds: 1_200_000_000)
        #expect(sink.notes.count == 1)   // the timeout found nothing left to send
    }

    @Test("Unattributed: every agent in the workspace is told, once")
    func broadcastOnce() async throws {
        let sink = SteeringSink()
        let s = steering(sink)
        s.observe(profileID: Self.ws, eventType: "egress.firewall", eventData: l4Deny())
        try await Task.sleep(nanoseconds: 150_000_000)
        s.observe(profileID: Self.ws, eventType: "egress.firewall", eventData: l4Deny())
        try await Task.sleep(nanoseconds: 150_000_000)
        #expect(sink.notes.count == 1)
        #expect(sink.notes.first?.window == nil)
        #expect(sink.notes.first?.soleOnly == false)
    }

    @Test("Request-level denials quote the rule by name and mention the advisor when it's on")
    func l7RuleNamed() {
        let sink = SteeringSink()
        let s = steering(sink, advisor: true)
        s.observe(profileID: Self.ws, eventType: "egress.firewall", eventData: [
            "action": .string("deny"), "layer": .string("l7"), "host": .string("api.github.com"),
            "port": .int(443), "method": .string("DELETE"), "path": .string("/repos/acme/app?x=secret"),
            "rule": .string("github"), "reason": .string("DELETE /repos/acme/app not permitted"),
        ])
        #expect(sink.notes.count == 1)
        let t = sink.notes[0].text
        #expect(t.contains("DELETE api.github.com/repos/acme/app"))
        #expect(!t.contains("secret"))
        #expect(t.contains("rule `github` (GitHub API): DELETE /repos/acme/app not permitted"))
        #expect(t.contains("http://policy.local"))
    }

    @Test("Allowed connections and cut flows say nothing")
    func notDenials() async throws {
        let sink = SteeringSink()
        let s = steering(sink)
        var allow = l4Deny(); allow["action"] = .string("allow")
        var cut = l4Deny(); cut["closed"] = .bool(true)
        s.observe(profileID: Self.ws, eventType: "egress.firewall", eventData: allow)
        s.observe(profileID: Self.ws, eventType: "egress.firewall", eventData: cut)
        s.observe(profileID: Self.ws, eventType: "net.flow", eventData: l4Deny())
        try await Task.sleep(nanoseconds: 150_000_000)
        #expect(sink.notes.isEmpty)
    }

    @Test("A sandbox denial goes to the agent in its chain; unattributed, only to a sole agent")
    func sandbox() {
        let sink = SteeringSink()
        let s = steering(sink)
        s.noteAgent(profileID: Self.ws, pid: 500, window: 1)
        s.noteSandboxDenial(profileID: Self.ws, frame: [
            "kind": "landlock_denied", "pid": 700, "ppid": 650, "comm": "cat", "path": "/etc/shadow",
            "op": "read", "sandboxed": true, "phase": "session",
            "chain": [["pid": 650, "comm": "bash"], ["pid": 500, "comm": "claude"]],
        ])
        s.noteSandboxDenial(profileID: Self.ws, frame: [
            "kind": "seccomp_denied", "pid": 40, "comm": "unshare", "syscall": 97, "sandboxed": true,
        ])
        #expect(sink.notes.count == 2)
        #expect(sink.notes[0].window == 1)
        #expect(sink.notes[0].text.contains("cat reading /etc/shadow"))
        #expect(sink.notes[0].text.contains("sudo"))
        #expect(sink.notes[1].window == nil && sink.notes[1].soleOnly)
        #expect(sink.notes[1].text.contains("unshare (#97)"))
    }

    @Test("Boot-time and out-of-sandbox denials are Bromure's own")
    func sandboxIgnored() {
        let sink = SteeringSink()
        let s = steering(sink)
        s.noteSandboxDenial(profileID: Self.ws, frame: ["kind": "landlock_denied", "pid": 1, "phase": "boot", "path": "/x"])
        s.noteSandboxDenial(profileID: Self.ws, frame: ["kind": "landlock_denied", "pid": 2, "sandboxed": false, "path": "/y"])
        #expect(sink.notes.isEmpty)
    }

    @Test("A probing loop is told a few times a minute, not drowned")
    func burst() {
        let sink = SteeringSink()
        let s = steering(sink)
        s.noteAgent(profileID: Self.ws, pid: 500, window: 1)
        for i in 0..<20 {
            s.noteSandboxDenial(profileID: Self.ws, frame: [
                "kind": "file_open_denied", "pid": 700 + i, "ppid": 500, "comm": "find",
                "path": "/root/dir\(i)/x", "op": "read", "sandboxed": true,
            ])
        }
        #expect(sink.notes.count == PolicySteering.burst)
    }

    @Test("The agent's own telemetry is not its doing: nothing is told, attributed or not")
    func agentTelemetry() async throws {
        let sink = SteeringSink()
        let s = steering(sink)
        s.noteAgent(profileID: Self.ws, pid: 500, window: 1)
        // Flushed by the agent process itself, seconds after a tool call.
        s.noteFlow(profileID: Self.ws, dst: "198.51.100.7", dport: 443, pids: [500, 400])
        s.observe(profileID: Self.ws, eventType: "egress.firewall",
                  eventData: l4Deny(host: "http-intake.logs.us5.datadoghq.com", ip: "198.51.100.7"))
        // Seen with no flow at all (sentry off): not told to everyone either.
        s.observe(profileID: Self.ws, eventType: "egress.firewall",
                  eventData: l4Deny(host: "statsig.anthropic.statsig.com", ip: "198.51.100.8"))
        try await Task.sleep(nanoseconds: 150_000_000)
        #expect(sink.notes.isEmpty)
        // A tool the agent ran reaching it is the agent's doing.
        s.noteFlow(profileID: Self.ws, dst: "198.51.100.9", dport: 443, pids: [900, 500])
        s.observe(profileID: Self.ws, eventType: "egress.firewall",
                  eventData: l4Deny(host: "api.datadoghq.com", ip: "198.51.100.9"))
        #expect(sink.notes.count == 1)
        #expect(sink.notes.first?.window == 1)
    }

    @Test("The agent process's own connection counts only right after a tool call (an in-process fetch)")
    func agentOwnConnection() {
        let sink = SteeringSink()
        let s = steering(sink)
        let t0 = Date()
        let clock = SteeringClock(t0)
        s.now = { clock.now }
        s.noteAgent(profileID: Self.ws, pid: 500, window: 2)
        clock.now = t0.addingTimeInterval(PolicySteering.toolQuiet + 5)
        s.noteFlow(profileID: Self.ws, dst: "203.0.113.9", dport: 443, pids: [500])
        s.observe(profileID: Self.ws, eventType: "egress.firewall", eventData: l4Deny())
        #expect(sink.notes.isEmpty)   // idle: background traffic
        // WebFetch: a PreToolUse, then the agent itself connects.
        s.noteAgent(profileID: Self.ws, pid: 500, window: 2)
        s.noteFlow(profileID: Self.ws, dst: "203.0.113.10", dport: 443, pids: [500])
        s.observe(profileID: Self.ws, eventType: "egress.firewall",
                  eventData: l4Deny(host: "other.example", ip: "203.0.113.10"))
        #expect(sink.notes.count == 1)
        #expect(sink.notes.first?.window == 2)
    }

    @Test("Through the guest's proxy bridge, the flow names its target by host and still finds the tab")
    func proxiedFlow() {
        let sink = SteeringSink()
        let s = steering(sink)
        s.attributionWait = 1
        s.noteAgent(profileID: Self.ws, pid: 500, window: 3)
        s.noteAgent(profileID: Self.ws, pid: 600, window: 5)
        s.observe(profileID: Self.ws, eventType: "egress.firewall",
                  eventData: ["action": .string("deny"), "layer": .string("sni"), "host": .string("example.com"),
                              "port": .int(443)])
        #expect(sink.notes.isEmpty)
        // NetworkLineage, once the bridge tagged curl's loopback port.
        s.noteFlow(profileID: Self.ws, dst: "host:example.com", dport: 443, pids: [910, 900, 500])
        #expect(sink.notes.count == 1)
        #expect(sink.notes.first?.window == 3)
    }

    @Test("The lineage's denied net.flow (root → leaf chain) attributes a denial waiting for it")
    func lineageFlow() {
        let sink = SteeringSink()
        let s = steering(sink)
        s.attributionWait = 3
        s.noteAgent(profileID: Self.ws, pid: 500, window: 4)
        s.noteAgent(profileID: Self.ws, pid: 600, window: 5)
        s.observe(profileID: Self.ws, eventType: "egress.firewall",
                  eventData: ["action": .string("deny"), "layer": .string("sni"), "host": .string("example.com"),
                              "dst_ip": .string("172.66.147.243"), "port": .int(443)])
        #expect(sink.notes.isEmpty)
        let chain: [AnyJSON] = [1, 400, 500, 800, 900].map { .object(["pid": .int($0)]) }
        s.observe(profileID: Self.ws, eventType: "net.flow", eventData: [
            "decision": .string("deny"), "dst": .string("172.66.147.243"), "host": .string("example.com"),
            "dport": .int(443), "processes": .array(chain),
        ])
        #expect(sink.notes.count == 1)
        #expect(sink.notes.first?.window == 4)
    }

    @Test("A sole agent is told at once, without waiting for the sentry's batched flow")
    func soleAgentAtOnce() {
        let sink = SteeringSink()
        let s = steering(sink)
        s.attributionWait = 60
        s.noteAgent(profileID: Self.ws, pid: 500, window: 1)
        s.observe(profileID: Self.ws, eventType: "egress.firewall", eventData: l4Deny())
        #expect(sink.notes.count == 1)
        #expect(sink.notes.first?.window == 1)
        // Its telemetry still isn't its doing.
        s.observe(profileID: Self.ws, eventType: "egress.firewall",
                  eventData: l4Deny(host: "http-intake.logs.us5.datadoghq.com", ip: "198.51.100.7"))
        #expect(sink.notes.count == 1)
    }

    @Test("A restarted agent's window follows its new pid")
    func agentRestart() {
        let sink = SteeringSink()
        let s = steering(sink)
        s.noteAgent(profileID: Self.ws, pid: 500, window: 1)
        s.noteAgent(profileID: Self.ws, pid: 510, window: 1)
        s.noteFlow(profileID: Self.ws, dst: "203.0.113.9", dport: 443, pids: [900, 500])
        s.observe(profileID: Self.ws, eventType: "egress.firewall", eventData: l4Deny())
        // pid 500 no longer speaks for window 1: not attributed, so every
        // agent is told.
        #expect(sink.notes.count == 1)
        #expect(sink.notes.first?.window == nil)
    }
}
