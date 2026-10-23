import Foundation
import Testing

/// Finding (CWE-670): "Ephemeral reboot is cancelled when launch waits on
/// Kimi or a remote prompt". A reboot tears the session down, then launches
/// the workspace again -- but the teardown deleted a `vm run --rm` workspace
/// as if it had stopped for good, so a launch that waited (Kimi
/// provisioning, a remote drift or compromise prompt) found it gone and never
/// booted, and a direct launch recreated it no longer ephemeral. A reboot now
/// keeps it, still ephemeral, through the teardown.
@Suite("vm run --rm: a reboot isn't the end of the workspace")
struct EphemeralRebootTests {
    private static let source = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("Sources/AgentCoding/BromureAC.swift")

    /// The body of `func <name>` (up to the next declaration at its indent).
    private func body(_ src: String, _ signature: String) throws -> Substring {
        let start = try #require(src.range(of: signature))
        let rest = src[start.upperBound...]
        let end = rest.range(of: "\n    func ") ?? rest.range(of: "\n    private func ") ?? rest.range(of: "\n    @MainActor")
        return rest[..<(end?.lowerBound ?? rest.endIndex)]
    }

    private func before(_ a: String, _ b: String, in s: Substring) -> Bool {
        guard let ra = s.range(of: a), let rb = s.range(of: b) else { return false }
        return ra.lowerBound < rb.lowerBound
    }

    @Test("the --rm delete skips a workspace that is rebooting")
    func teardownKeepsRebooting() throws {
        let src = try String(contentsOf: Self.source, encoding: .utf8)
        let stopped = try body(src, "func handleSessionStopped(profileID: Profile.ID) {")
        #expect(stopped.contains("if !rebootingProfiles.contains(profileID), ephemeralProfiles.remove(profileID) != nil,"))
    }

    @Test("both detached reboot paths mark the workspace across their teardown, and clear it before the launch")
    func rebootPathsMarkIt() throws {
        let src = try String(contentsOf: Self.source, encoding: .utf8)
        let remote = try body(src, "func rebootMachine(_ id: Profile.ID, force: Bool, remoteInitiated: Bool) async")
        #expect(before("rebootingProfiles.insert(id)", "await stopSession(id, action: .shutdown)", in: remote))
        #expect(before("rebootingProfiles.insert(id)", "handleSessionStopped(profileID: id)", in: remote))
        #expect(before("rebootingProfiles.remove(id)", "launch(profile, detached: !wasAttached", in: remote))
        #expect(before("handleSessionStopped(profileID: id)", "rebootingProfiles.remove(id)", in: remote))

        let guest = try body(src, "private func relaunchAfterGuestReboot(_ profileID: Profile.ID) {")
        #expect(before("rebootingProfiles.insert(profileID)", "handleSessionStopped(profileID: profileID)", in: guest))
        #expect(before("handleSessionStopped(profileID: profileID)", "rebootingProfiles.remove(profileID)", in: guest))
        #expect(before("rebootingProfiles.remove(profileID)", "self.launch(profile, detached: true)", in: guest))
    }

    /// Review of the above: kept through the teardown, a workspace whose
    /// relaunch then gave up (a stop while it waited, a prompt cancelled or
    /// skipped) was never booted, so its stop never came and it stayed on
    /// disk for good. Every place a launch gives up drops it.
    @Test("a launch that gives up deletes a --rm workspace that isn't running")
    func abandonedLaunchDeletes() throws {
        let src = try String(contentsOf: Self.source, encoding: .utf8)
        let drop = try body(src, "private func dropAbandonedEphemeral(_ id: Profile.ID) {")
        #expect(drop.contains("guard runningSessions[id] == nil, !diskInUse(id), !rebootingProfiles.contains(id),"))
        #expect(drop.contains("ephemeralProfiles.remove(id) != nil") && drop.contains("try? store.delete(p)"))
        // Kimi provisioning stopped, the boot remedy stopped, a wipe
        // cancelled (remote and local), a wipe or an upgrade skipped (remote).
        #expect(src.contains("""
            guard stop == nil, self.profiles.contains(where: { $0.id == profile.id }) else {
                                self.dropAbandonedEphemeral(profile.id); return
            """))
        #expect(src.contains("guard stop == nil else { self.dropAbandonedEphemeral(profileID); return }"))
        #expect(src.components(separatedBy: "case .cancelled: dropAbandonedEphemeral(profile.id); return").count == 3)
        let prompts = try body(src, "@MainActor private func resolveRemoteLaunchPrompts(")
        #expect(prompts.components(separatedBy: "dropAbandonedEphemeral(profile.id)").count == 4)
    }
}
