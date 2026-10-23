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
}
