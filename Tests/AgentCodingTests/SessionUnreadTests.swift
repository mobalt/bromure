import Foundation
import Testing
@testable import bromure_ac

/// Board task "Mark unread messages in the list of sessions": a session whose
/// agent finished a turn or stopped to ask shows an unread mark until someone
/// looks -- counted on the server, read from any client, the mark gone on
/// every other one; not shown while the agent works.
@Suite("Session unread marks")
@MainActor
struct SessionUnreadTests {
    static func tempStore() -> AgentSessionStore {
        AgentSessionStore(fileURL: FileManager.default.temporaryDirectory
            .appendingPathComponent("sessions-\(UUID().uuidString).json"))
    }

    static func roster(_ id: UUID, _ tabs: [TabsModel.Tab]) -> SessionListModel.VMEntry {
        let m = TabsModel(); m.tabs = tabs; m.rosterLive = true
        return SessionListModel.VMEntry(id: id, name: "ws", accentHex: "#000000", model: m)
    }

    @Test("what counts as a reply: a turn that ended, or a question -- for every agent's hooks")
    func replies() {
        let r = ACAppDelegate.isReply(from:to:)
        #expect(r(.working, .done))
        #expect(r(.working, .needsInput))
        #expect(r(.done, .needsInput))
        #expect(r(nil, .needsInput))
        #expect(!r(.needsInput, .needsInput))        // the same question again
        #expect(!r(.done, .done))                    // a settle re-reported
        #expect(!r(nil, .done))                      // a replayed status at launch
        #expect(!r(.done, .working))
        #expect(!r(.needsInput, .done))              // answered, not a new reply
    }

    @Test("the count goes up per reply; a read catches up to what was seen, never back, never past")
    func counting() {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("sessions-\(UUID().uuidString).json")
        let store = AgentSessionStore(fileURL: url)
        let s = AgentSession(profileID: UUID(), tool: .codex, title: "t", cwd: "~")
        store.upsert(s)
        #expect(store.session(s.id)?.isUnread == false)
        #expect(!store.markRead(s.id))                         // nothing to read
        store.noteReply(s.id); store.noteReply(s.id)
        #expect(store.session(s.id)?.replies == 2)
        #expect(store.session(s.id)?.isUnread == true)
        // A client saw 1 of them; a reply landed in between: still unread.
        #expect(store.markRead(s.id, upTo: 1))
        #expect(store.session(s.id)?.isUnread == true)
        #expect(!store.markRead(s.id, upTo: 0))                // never back
        #expect(store.markRead(s.id, upTo: 9))                 // never past the count
        #expect(store.session(s.id)?.readReplies == 2)
        #expect(store.session(s.id)?.isUnread == false)
        // A dialog waiting on the user is the agent asking.
        var heard: [UUID] = []
        store.onReply = { heard.append($0) }
        store.setAwaitingAnswer(s.id, true)
        #expect(store.session(s.id)?.isUnread == true && heard == [s.id])
        store.setAwaitingAnswer(s.id, true)                    // no change, no reply
        #expect(store.session(s.id)?.replies == 3)
        // Persisted with the session; an old file without them reads as read.
        let relaunched = AgentSessionStore(fileURL: url)
        #expect(relaunched.session(s.id)?.replies == 3 && relaunched.session(s.id)?.readReplies == 2)
        let old = try? JSONDecoder().decode(AgentSession.self, from: Data(
            #"{"id":"\#(UUID().uuidString)","profileID":"\#(UUID().uuidString)","tool":"claude","title":"t","cwd":"~","createdAt":0}"#.utf8))
        #expect(old?.isUnread == false)
    }

    @Test("a mirror never counts on its own: only the server does")
    func mirrorDoesntCount() {
        let mirror = AgentSessionStore(mirror: true)
        let s = AgentSession(profileID: UUID(), tool: .grok, title: "t", cwd: "~")
        mirror.applyMirror([s])
        mirror.noteReply(s.id)
        #expect(mirror.session(s.id)?.replies == nil)
    }

    @Test("the mark shows when the agent is done or asking, not while it works, not archived")
    func shownOnlyWhenNotWorking() {
        let store = Self.tempStore()
        let ws = UUID()
        var s = AgentSession(profileID: ws, tool: .omp, title: "t", cwd: "~/w", windowIndex: 1)
        s.agentAlive = true
        s.replies = 1
        store.upsert(s)
        let tab = TabsModel.Tab(label: "omp", index: 1, cwd: "/home/ubuntu/w")
        let model = SessionListModel()
        model.headlessEntries = [Self.roster(ws, [TabsModel.Tab(label: "bash", index: 0, cwd: "/home/ubuntu"), tab])]
        model.profileRows = [SessionListModel.ProfileRow(id: ws, name: "QA", accentHex: "#000000",
                                                         state: .running, compromised: false)]
        tab.agentStatus = .done
        #expect(SessionHome.showsUnread(store.session(s.id)!, in: model))
        tab.agentStatus = .needsInput
        #expect(SessionHome.showsUnread(store.session(s.id)!, in: model))
        tab.agentStatus = .working
        #expect(!SessionHome.showsUnread(store.session(s.id)!, in: model))
        tab.agentStatus = .done
        store.mutate(s.id) { $0.archivedAt = Date() }
        #expect(!SessionHome.showsUnread(store.session(s.id)!, in: model))
        store.mutate(s.id) { $0.archivedAt = nil }
        store.markRead(s.id)
        #expect(!SessionHome.showsUnread(store.session(s.id)!, in: model))
    }

    /// A /state as a server sends it (with its workspace list: one without is
    /// skipped as degenerate).
    static func snapshot(_ s: AgentSession) -> [String: Any] {
        ["workspaces": [] as [[String: Any]], "vms": [] as [[String: Any]], "workspacesListed": true,
         "agentSessions": [wire(s)]]
    }

    static func wire(_ s: AgentSession) -> [String: Any] {
        let enc = JSONEncoder(); enc.dateEncodingStrategy = .iso8601
        return (try? JSONSerialization.jsonObject(with: enc.encode(s))) as? [String: Any] ?? [:]
    }

    @Test("a client's read shows at once and isn't undone by a snapshot that predates it; another client sees the server's")
    func clientRead() {
        let a = RemoteHostController(host: RemoteHost(name: "a", address: "127.0.0.1", port: 1, user: "nobody"))
        let b = RemoteHostController(host: RemoteHost(name: "b", address: "127.0.0.1", port: 1, user: "nobody"))
        var s = AgentSession(profileID: UUID(), tool: .claude, title: "t", cwd: "~")
        s.replies = 2
        for c in [a, b] { c.applyPushedSnapshot(Self.snapshot(s)) }
        #expect(a.sessionStore.session(s.id)?.isUnread == true)
        a.markRead(s.id)
        #expect(a.sessionStore.session(s.id)?.isUnread == false)
        // The server hasn't caught up yet: the read holds.
        a.applyPushedSnapshot(Self.snapshot(s))
        #expect(a.sessionStore.session(s.id)?.isUnread == false)
        // The server took it: every client's next snapshot has it read.
        s.readReplies = 2
        for c in [a, b] { c.applyPushedSnapshot(Self.snapshot(s)) }
        #expect(b.sessionStore.session(s.id)?.isUnread == false)
        // A new reply: unread again everywhere.
        s.replies = 3
        a.applyPushedSnapshot(Self.snapshot(s))
        #expect(a.sessionStore.session(s.id)?.isUnread == true)
        // The session on screen is read as the reply arrives.
        a.watching = { s.id }
        s.replies = 4
        a.applyPushedSnapshot(Self.snapshot(s))
        #expect(a.sessionStore.session(s.id)?.isUnread == false)
    }

    @Test("wiring: the hook choke point counts, the server route reads, viewing reads on every client")
    func wiring() throws {
        let top = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        func src(_ p: String) throws -> String { try String(contentsOf: top.appendingPathComponent(p), encoding: .utf8) }
        let ac = try src("Sources/AgentCoding/BromureAC.swift")
        let set = try #require(ac.range(of: "func setTabAgentStatus(_ id: Profile.ID, index: Int, _ status: AgentStatus) {"))
        #expect(ac[set.upperBound...].prefix(1200).contains("agentSessionStore.noteReply(s.id)"))
        #expect(ac.contains("case (let sid?, \"read\"):"))
        #expect(ac.contains("self.markSessionRead(sid, upTo: body[\"seen\"] as? Int)"))
        #expect(ac.contains("if self.sessionOnScreen == id { self.agentSessionStore.markRead(id) }"))
        let host = try src("Sources/AgentCoding/UnifiedSessionWindow.swift")
        #expect(host.components(separatedBy: "delegate.markSessionRead(id)").count == 3)   // both select paths
        #expect(host.contains("acDelegate?.markSessionRead(id)"))                           // becomeKey
        let fc = try src("Sources/AgentCoding/FatClientController.swift")
        #expect(fc.components(separatedBy: "controller.markRead(id)").count >= 4)           // selects + becomeKey
        #expect(fc.contains("controller.watching = { [weak self] in self?.sessionOnScreen }"))
        let ios = try src("ios/BromureRemote/Sources/BromureRemote/SessionScreens.swift")
        #expect(ios.contains(".onChange(of: session?.replies) { _, _ in markRead() }"))
        #expect(ios.contains("if scenePhase == .active { controller.markRead(sessionID) }"))
    }
}
