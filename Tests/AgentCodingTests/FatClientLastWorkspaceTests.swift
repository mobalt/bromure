import Foundation
import Testing
@testable import bromure_ac

/// Finding: deleting the last workspace from a fat client left it in the
/// mirror for good — every later /state listed no workspaces, and the
/// client skipped any empty list as a truncated read, so the row stayed
/// (and the snapshot's sessions, tasks and grid were never applied).
@Suite("Fat client: deleting the last workspace")
@MainActor
struct FatClientLastWorkspaceTests {
    private func controller(with id: UUID) -> RemoteHostController {
        let c = RemoteHostController(host: RemoteHost(name: "t", address: "127.0.0.1", port: 1, user: "nobody"))
        c.applyPushedSnapshot(["workspaces": [["id": id.uuidString, "name": "only", "tool": "claude",
                                               "authMode": "token", "state": "off"]],
                               "vms": [], "workspacesListed": true])
        return c
    }

    @Test("a listed, empty workspaces array removes the last row")
    func emptyListIsReal() {
        let id = UUID()
        let c = controller(with: id)
        #expect(c.profile(for: id) != nil)
        c.applyPushedSnapshot(["workspaces": [] as [[String: Any]], "vms": [], "workspacesListed": true])
        #expect(c.profile(for: id) == nil)
        #expect(c.listModel.profileRows.isEmpty)
        // An older host (no workspacesListed): a present, empty array is real too.
        let d = controller(with: id)
        d.applyPushedSnapshot(["workspaces": [] as [[String: Any]], "vms": []])
        #expect(d.profile(for: id) == nil)
    }

    @Test("a truncated snapshot, or a host that didn't list, keeps the rows")
    func truncatedKeepsRows() {
        let id = UUID()
        let c = controller(with: id)
        c.applyPushedSnapshot(["vms": []])
        #expect(c.profile(for: id) != nil)
        c.applyPushedSnapshot(["workspaces": [] as [[String: Any]], "vms": [], "workspacesListed": false])
        #expect(c.profile(for: id) != nil)
        #expect(c.listModel.profileRows.count == 1)
    }

    /// Finding (CWE-754): with no workspace left, the guard was disarmed —
    /// a truncated poll (`[:]`) wiped the board, the grid and the sessions
    /// stage, and cancelled a sign-in in progress.
    @Test("with no workspace left, a truncated snapshot still keeps the mirror")
    func truncatedKeepsEmptyMirror() {
        let c = controller(with: UUID())
        c.applyPushedSnapshot(["workspaces": [] as [[String: Any]], "vms": [], "workspacesListed": true,
                               "agentSessions": [] as [[String: Any]]])
        #expect(c.listModel.profileRows.isEmpty)
        #expect(c.supportsSessions)
        let rev = c.revision
        c.applyPushedSnapshot([:])
        c.applyPushedSnapshot(["vms": []])
        c.applyPushedSnapshot(["workspaces": [] as [[String: Any]], "workspacesListed": false])
        #expect(c.supportsSessions)
        #expect(c.revision == rev)
    }

    @Test("a successful delete drops the row at once")
    func deleteDropsRow() {
        let id = UUID()
        let c = controller(with: id)
        c.workspaceDeleted(id)
        #expect(c.profile(for: id) == nil)
        #expect(c.listModel.profileRows.isEmpty)
    }
}
