import Foundation
import Testing
@testable import bromure_ac

/// Finding (CWE-670): "Home size stays shrinkable after the image exists".
/// The editor's floor came from a storage snapshot taken when it opened:
/// opened before the first boot (or after an erase), then left open while
/// the workspace booted, it still offered 8 GB and saved a size below the
/// new image -- one the disk layer never applies (it only grows), so it only
/// came back as the size of the next home after an erase. Now the snapshot
/// is measured again, the draft is held to the image, and the store refuses
/// to keep a setting below it whoever saves.
@Suite("Home size can't be saved below an image created after the editor opened")
struct HomeSizeAfterImageTests {
    static func tempStore() -> (ProfileStore, URL) {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("hsi-\(UUID().uuidString)")
        return (ProfileStore(rootDir: root), root)
    }

    /// A sparse home image of `gb` GiB, as SessionDisk creates it.
    static func makeImage(_ store: ProfileStore, _ p: Profile, gb: Int) throws {
        let url = store.homeImageURL(for: p)
        #expect(FileManager.default.createFile(atPath: url.path, contents: nil))
        let h = try FileHandle(forWritingTo: url)
        try h.truncate(atOffset: UInt64(gb) << 30)
        try h.close()
    }

    @Test("a save below the image keeps the image's size; above it, or with no image, stays as set")
    func storeHoldsToImage() throws {
        let (store, root) = Self.tempStore()
        defer { try? FileManager.default.removeItem(at: root) }
        var p = Profile(name: "h", tool: .claude, authMode: .token)
        p.homeModel = .ext4
        p.homeImageGB = 8
        try store.save(p)

        var noImage = p
        try store.saveEdited(&noImage)
        #expect(noImage.homeImageGB == 8)                   // not created yet: any size from 8

        try Self.makeImage(store, p, gb: 64)                // the workspace booted meanwhile
        var stale = p
        try store.saveEdited(&stale)
        #expect(stale.homeImageGB == 64)
        #expect(store.storedProfile(id: p.id)?.homeImageGB == 64)

        var bigger = p
        bigger.homeImageGB = 128
        try store.saveEdited(&bigger)
        #expect(store.storedProfile(id: p.id)?.homeImageGB == 128)
        var unset = p
        unset.homeImageGB = nil
        try store.saveEdited(&unset)
        #expect(store.storedProfile(id: p.id)?.homeImageGB == nil)   // the default stays the default
    }

    @Test("the editor holds its draft to the image it now sees")
    func draftClamp() {
        let s = ProfileEditorView.homeSetting(_:existingGB:saved:)
        #expect(s(8, nil, nil) == 8)            // no image: as chosen
        #expect(s(8, 64, 8) == 64)              // below the image: its size
        #expect(s(8, 64, nil) == nil)           // = the size it would follow anyway
        #expect(s(128, 64, nil) == 128)
        #expect(s(nil, 64, nil) == nil)
    }

    @Test("the storage is measured again on show, erase, start and stop, locally and from a fat client")
    func remeasured() throws {
        let top = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        func src(_ p: String) throws -> String { try String(contentsOf: top.appendingPathComponent(p), encoding: .utf8) }
        let views = try src("Sources/AgentCoding/ProfileViews.swift")
        #expect(views.contains(".task(id: storageRevision) { await remeasureStorage() }"))
        #expect(views.contains("if (note.object as? UUID) == draft.id { storageRevision += 1 }"))
        #expect(views.contains("guard let u = currentStorage?.profileHomeImageURL"))
        #expect(views.contains("out.homeImageGB = Self.homeSetting(out.homeImageGB, existingGB: homeCapacityGB"))
        let ac = try src("Sources/AgentCoding/BromureAC.swift")
        #expect(ac.contains("context.remeasure = { [weak self] in self?.makeStorageContext(for: editing) }"))
        let register = try #require(ac.range(of: "func registerSession("))
        #expect(ac[register.upperBound...].prefix(1800).contains("post(name: .bromureWorkspaceStorageChanged, object: profile.id)"))
        let unregister = try #require(ac.range(of: "func unregisterSession("))
        #expect(ac[unregister.upperBound...].prefix(500).contains("post(name: .bromureWorkspaceStorageChanged, object: id)"))
        let fc = try src("Sources/AgentCoding/FatClientController.swift")
        #expect(fc.contains("c.remeasure = { [weak self] in await self?.fetchStorageContext(id) }"))
        #expect(fc.contains("post(name: .bromureWorkspaceStorageChanged, object: r.id)"))
    }

    /// Finding (CWE-362): "A slower home-size remeasure can drop the floor
    /// back below the image". Two remeasures in flight (the pane showed, then
    /// the workspace started): the older one, from before the image existed,
    /// answered last and was applied over the newer one.
    @Test("an older remeasure that answers last is dropped")
    @MainActor
    func staleRemeasureDropped() async {
        let lands = ProfileEditorView.remeasureLands(asked:now:cancelled:)
        #expect(lands(3, 3, false))
        #expect(!lands(3, 4, false))                       // a newer one was asked for since
        #expect(!lands(3, 3, true))                        // its view task was cancelled

        // The race, the way the editor runs it: revision 1 (no image yet) is
        // slow, revision 2 (image there) is fast.
        let editor = RaceEditor()
        let old = Task { await editor.remeasure(answer: nil, delay: .milliseconds(200)) }
        try? await Task.sleep(for: .milliseconds(20))
        let new = Task { await editor.remeasure(answer: 64, delay: .milliseconds(10)) }
        await old.value
        await new.value
        #expect(editor.applied == 64)
    }

    /// The editor's remeasure, minus SwiftUI: the home capacity it applies.
    @MainActor
    final class RaceEditor {
        var revision = 0
        var applied: Int? = nil
        func remeasure(answer: Int?, delay: Duration) async {
            revision += 1
            let asked = revision
            try? await Task.sleep(for: delay)
            guard ProfileEditorView.remeasureLands(asked: asked, now: revision, cancelled: Task.isCancelled) else { return }
            applied = answer
        }
    }

    @Test("the editor and the fat client's fetch both drop a superseded answer")
    func staleRemeasureWiring() throws {
        let top = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        func src(_ p: String) throws -> String { try String(contentsOf: top.appendingPathComponent(p), encoding: .utf8) }
        let views = try src("Sources/AgentCoding/ProfileViews.swift")
        #expect(views.contains("Self.remeasureLands(asked: asked, now: storageRevision, cancelled: Task.isCancelled)"))
        #expect(try src("Sources/AgentCoding/FatClientController.swift").contains("}).value, !Task.isCancelled,"))
    }
}
