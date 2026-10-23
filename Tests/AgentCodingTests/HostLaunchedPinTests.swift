import Foundation
import Testing
@testable import bromure_ac

/// Finding (CWE-807): "Guest-adopted tmux windows are spared from pid-pin
/// eviction, so a guest can still fill every slot". The windows a host tab's
/// agent may evict a pin for were every live session's -- and the store
/// adopts any guest tmux window labelled as an agent, @display and
/// @worktree included. 64 such windows held every slot for good. Only a tab
/// a launch of the host's own bound is spared now.
@Suite("Policy steering: only host-launched tabs are spared")
@MainActor
struct HostLaunchedPinTests {
    private func roster(_ id: UUID, _ tabs: [TabsModel.Tab]) -> SessionListModel.VMEntry {
        let model = TabsModel()
        model.tabs = tabs
        model.rosterLive = true
        return SessionListModel.VMEntry(id: id, name: "ws", accentHex: "#000000", model: model)
    }

    @Test("adopted guest tabs aren't host windows, whatever their options say; the launched one is")
    func adoptedArentSpared() {
        let store = AgentSessionStore(fileURL: FileManager.default.temporaryDirectory
            .appendingPathComponent("sessions-\(UUID().uuidString).json"))
        let ws = UUID()
        var launch = AgentSession(profileID: ws, tool: .claude, title: "Fix login", cwd: "~/app")
        launch.launchingSince = Date(); launch.launchBaselineIndex = 0; launch.launchDisplay = "Fix login"
        store.upsert(launch)
        let shell = TabsModel.Tab(label: "bash", index: 0, cwd: "/home/ubuntu")
        let mine = TabsModel.Tab(label: "claude", index: 1, cwd: "/home/ubuntu/app", display: "Fix login")
        // Guest-made windows: an agent @label, a @display, a wt/ @worktree.
        let squatters = (2..<70).map { i in
            TabsModel.Tab(label: "claude", index: i, cwd: "/home/ubuntu/w\(i)",
                          worktreeBranch: i.isMultiple(of: 2) ? "wt/x\(i)" : nil,
                          display: i.isMultiple(of: 3) ? "Squat \(i)" : nil)
        }
        store.reconcile(entries: [roster(ws, [shell, mine] + squatters)])
        #expect(store.session(launch.id)?.windowIndex == 1)
        #expect(store.sessions.filter { $0.profileID == ws && $0.windowIndex != nil }.count > PolicySteering.pinCap)
        let host = ACAppDelegate.hostAgentWindows(store.sessions, profileID: ws)
        #expect(host == [1])

        // The guest's windows fill every slot; the host tab's agent still gets one.
        let s = PolicySteering()
        for (n, t) in squatters.prefix(PolicySteering.pinCap).enumerated() {
            s.noteAgent(profileID: ws, pid: 9_000 + n, window: t.index, hostWindows: host)
        }
        s.noteAgent(profileID: ws, pid: 500, window: 1, hostWindows: host)
        #expect(s.agentWindows(profileID: ws).contains(1))

        // Rebound anywhere else (a lost binding taken back, a twin merge):
        // no longer the tab the launch opened.
        store.mutate(launch.id) { $0.windowIndex = nil }
        store.mutate(launch.id) { $0.windowIndex = 1 }
        #expect(ACAppDelegate.hostAgentWindows(store.sessions, profileID: ws).isEmpty)
    }

    @Test("only the launch binding marks a tab as the host's")
    func onlyStep2Marks() throws {
        let src = try String(contentsOf: URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/AgentCoding/AgentSessions.swift"), encoding: .utf8)
        #expect(src.components(separatedBy: "hostLaunchedWindow = tab.index").count == 2)
        #expect(src.contains("s.windowIndex = tab.index\n                        s.hostLaunchedWindow = tab.index"))
    }
}
