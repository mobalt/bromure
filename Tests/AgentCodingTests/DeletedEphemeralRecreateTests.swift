import Foundation
import Testing
@testable import bromure_ac

/// Finding (CWE-459): "The other Bromure process recreates a deleted vm run
/// --rm workspace, including its secrets". The GUI and the login agent share
/// one store, each with its own `profiles`. One's sweep deleted a stopped
/// `--rm` workspace; the other still listed it, and Start (sidebar, fat
/// client, automation) reached `launch`, whose `store.touch` → `save`
/// recreated the directory with profile.json and secrets.enc -- without the
/// `ephemeral` marker, so it came back as a kept workspace.
@Suite("A workspace the other process deleted stays deleted")
struct DeletedEphemeralRecreateTests {
    @Test("touch on a deleted workspace refuses and writes nothing")
    func touchDoesNotRecreate() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("gone-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let store = ProfileStore(rootDir: root)
        let p = Profile(name: "rm-run", tool: .claude, authMode: .token)
        try store.save(p)
        store.markEphemeral(p)
        #expect(store.exists(p))
        try store.touch(p)                       // still there: stamped
        // The other process's sweep.
        try store.delete(p)
        #expect(throws: ProfileStore.ProfileGone.self) { try store.touch(p) }
        #expect(!FileManager.default.fileExists(atPath: store.profileDirectory(for: p).path))
        #expect(!store.exists(p))
        #expect(store.loadAll().isEmpty)
        #expect(ProfileStore.ProfileGone(name: "rm-run").localizedDescription.contains("rm-run"))
    }

    @Test("launch checks the disk before it asks or boots, and again at touch; an edit doesn't write it back")
    func wiring() throws {
        let src = try String(contentsOf: URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/AgentCoding/BromureAC.swift"), encoding: .utf8)
        let start = try #require(src.range(of: "    func launch(_ profile: Profile, detached: Bool = false,"))
        let body = src[start.upperBound...]
        let check = try #require(body.range(of: "guard store.exists(profile) else { forgetDeletedProfile(profile, unattended: unattended); return }"))
        let firstPrompt = try #require(body.range(of: "alert.runModal()"))
        #expect(check.lowerBound < firstPrompt.lowerBound)
        #expect(body.contains("do { try store.touch(profile) } catch is ProfileStore.ProfileGone {"))
        #expect(!src.contains("try? store.touch(profile)"))
        let persist = try #require(src.range(of: "func persistEditedProfile("))
        #expect(src[persist.upperBound...].prefix(1200).contains("if editing != nil, !store.exists(profile) {"))
    }
}
