import Foundation
import Testing
@testable import bromure_ac

// A room's focus must not jump to another member because the focused one
// went missing from a single snapshot (a failed poll, a restart): the user's
// typing then landed in someone else's chat.

@MainActor
private final class FakeRoomBackend: RoomStageBackend {
    let roomStore: AgentRoomStore
    var roomSessions: [AgentSession] = []
    init(store: AgentRoomStore) { roomStore = store }
    func chatKey(for s: AgentSession) -> String? { nil }
    func makeChat(for s: AgentSession) -> BeautifiedSessionModel? { nil }
    func startSwitchboard(_ room: AgentRoom) {}
    func setLayout(_ room: UUID, _ layout: String) {}
    func wake(_ s: AgentSession, with text: String) {}
    func restingTranscript(for s: AgentSession, ended: Bool) async -> Data? { nil }
    func peerMentions(for s: AgentSession) -> [PeerMention] { [] }
    func assignNickname(_ id: UUID, _ nick: String) {}
}

@Suite("Room focus")
@MainActor
struct RoomFocusTests {

    @Test("a member missing from one or two refreshes keeps focus and zoom; gone for good, focus moves")
    func focusSurvivesFlicker() {
        let store = AgentRoomStore(fileURL: FileManager.default.temporaryDirectory
            .appendingPathComponent("rooms-\(UUID().uuidString).json"))
        let room = store.create(name: "R")
        let ws = UUID()
        var a = AgentSession(profileID: ws, tool: .claude, title: "a")
        a.roomID = room.id
        var b = AgentSession(profileID: ws, tool: .claude, title: "b")
        b.roomID = room.id
        b.createdAt = a.createdAt.addingTimeInterval(10)
        let backend = FakeRoomBackend(store: store)
        backend.roomSessions = [a, b]
        let c = RoomStageController(roomID: room.id, backend: backend, listModel: SessionListModel())
        c.focus(b.id)
        c.zoomedID = b.id

        // b drops out of two snapshots: nothing moves.
        backend.roomSessions = [a]
        c.refresh(); c.refresh()
        #expect(c.focusedID == b.id)
        #expect(c.zoomedID == b.id)
        // Back again: the count starts over.
        backend.roomSessions = [a, b]
        c.refresh()
        backend.roomSessions = [a]
        c.refresh(); c.refresh()
        #expect(c.focusedID == b.id)
        // Really gone: focus moves to the first member, zoom ends.
        c.refresh()
        #expect(c.focusedID == a.id)
        #expect(c.zoomedID == nil)
        c.stop()
    }

    /// Finding (CWE-670): "Reading a session inside a room never clears its
    /// unread mark". What a room shows is what's read: the page's cells (or
    /// the zoomed one), and the Switchboard while its chat is on show.
    @Test("a room's on-screen chats: the page, the zoomed cell, none behind the 1x1 Switchboard tab")
    func onScreen() throws {
        let store = AgentRoomStore(fileURL: FileManager.default.temporaryDirectory
            .appendingPathComponent("rooms-\(UUID().uuidString).json"))
        let room = store.create(name: "R")
        let ws = UUID()
        var a = AgentSession(profileID: ws, tool: .claude, title: "a"); a.roomID = room.id
        var b = AgentSession(profileID: ws, tool: .codex, title: "b"); b.roomID = room.id
        b.createdAt = a.createdAt.addingTimeInterval(10)
        let backend = FakeRoomBackend(store: store)
        backend.roomSessions = [a, b]
        let c = RoomStageController(roomID: room.id, backend: backend, listModel: SessionListModel())
        var told = 0
        c.onShownChanged = { told += 1 }
        #expect(Set(c.onScreenIDs) == [a.id, b.id])
        c.zoomedID = b.id
        #expect(c.onScreenIDs == [b.id] && told == 1)
        c.zoomedID = nil
        c.cellsHidden = true                       // the 1x1 Switchboard tab is up
        #expect(c.onScreenIDs.isEmpty && told == 3)
        c.switchboardOnScreen = true               // a sleeping Switchboard (no chat): nothing read
        #expect(c.onScreenIDs.isEmpty && told == 4)
        c.switchboardOnScreen = true               // no change, no call
        #expect(told == 4)
        // A member joins the page on show: a refresh says so (once).
        c.cellsHidden = false
        told = 0
        var d = AgentSession(profileID: ws, tool: .grok, title: "d"); d.roomID = room.id
        d.createdAt = b.createdAt.addingTimeInterval(10)
        backend.roomSessions = [a, b, d]
        c.refresh()
        #expect(c.onScreenIDs.contains(d.id) && told == 1)
        c.refresh()
        #expect(told == 1)
        c.stop()

        let top = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let stage = try String(contentsOf: top.appendingPathComponent("Sources/AgentCoding/RoomStage.swift"), encoding: .utf8)
        #expect(stage.contains("if switchboardOnScreen, let sb = switchboard, models[sb.id] != nil { ids.append(sb.id) }"))
        #expect(stage.contains(".onChange(of: switchboardShown, initial: true) { _, v in controller.switchboardOnScreen = v }"))
        #expect(stage.contains(".onChange(of: singleLayout && switchboardTab, initial: true) { _, v in controller.cellsHidden = v }"))
        #expect(stage.contains(".onAppear { controller.onShownChanged?() }"))
        let ios = try String(contentsOf: top.appendingPathComponent("ios/BromureRemote/Sources/BromureRemote/RoomScreens.swift"), encoding: .utf8)
        #expect(ios.contains("if dockOpen, zoomedID == nil, let sb = switchboard, MobileRooms.isLive(sb, controller) { shown.append(sb) }"))
        #expect(ios.contains("for s in onScreen where s.isUnread { controller.markRead(s.id) }"))
    }
}
