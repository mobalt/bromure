import Foundation
import Testing
@testable import bromure_ac

/// The fat client rebuilds a workspace's attached browser when it detects the
/// workspace VM rebooted, inferred from the mirrored `uptimeSeconds` resetting
/// (its derived boot time jumping forward). Guards against false positives —
/// steady running, poll jitter, and clock-offset drift must NOT read as a
/// reboot, or the browser pane would spuriously rebuild.
@Suite("Workspace reboot detection")
struct WorkspaceRebootDetectTests {
    let now = Date(timeIntervalSince1970: 1_700_000_000)

    @Test("Uptime reset (boot time jumps well forward) = reboot")
    func rebootDetected() {
        // Was up ~1h (boot 3600s ago); now up ~2s (boot ≈ now) → big forward jump.
        let prev = now.addingTimeInterval(-3600)
        let fresh = now.addingTimeInterval(-2)
        #expect(RemoteHostController.uptimeDidReset(prevBoot: prev, newBoot: fresh))
    }

    @Test("Steady running (boot time ~constant) is NOT a reboot")
    func steadyRunning() {
        // Each poll derives ~the same boot time (uptime grows in lockstep with now).
        let prev = now.addingTimeInterval(-3600)
        #expect(!RemoteHostController.uptimeDidReset(prevBoot: prev, newBoot: prev))
        #expect(!RemoteHostController.uptimeDidReset(prevBoot: prev,
                                                     newBoot: prev.addingTimeInterval(1)))
    }

    @Test("Small forward jitter / clock drift under the floor is NOT a reboot")
    func jitterIgnored() {
        let prev = now.addingTimeInterval(-600)
        #expect(!RemoteHostController.uptimeDidReset(prevBoot: prev,
                                                     newBoot: prev.addingTimeInterval(3)))
        #expect(!RemoteHostController.uptimeDidReset(prevBoot: prev,
                                                     newBoot: prev.addingTimeInterval(19)))
        // Just past the floor counts (a real, if short-lived, uptime reset).
        #expect(RemoteHostController.uptimeDidReset(prevBoot: prev,
                                                    newBoot: prev.addingTimeInterval(21)))
    }

    @Test("A backward drift (boot time earlier) is never a reboot")
    func backwardNotReboot() {
        let prev = now
        #expect(!RemoteHostController.uptimeDidReset(prevBoot: prev,
                                                     newBoot: prev.addingTimeInterval(-100)))
    }

    /// Board report: over a slow P2P relay the boot screen flashed every few
    /// seconds — a reply arriving 20 s+ late made `now − uptime` jump forward,
    /// read as a reboot. The host's own boot stamp doesn't move with latency.
    @Test("The host's boot stamp: only a new boot moves it, however late the reply")
    func bootStamp() {
        let booted = now.timeIntervalSince1970 - 3600
        #expect(!RemoteHostController.bootStampMoved(prev: booted, new: booted))
        #expect(!RemoteHostController.bootStampMoved(prev: booted, new: booted - 30))
        #expect(RemoteHostController.bootStampMoved(prev: booted, new: now.timeIntervalSince1970))
    }

    @Test("A late reply from a host that stamps its boot is not a reboot")
    @MainActor func lateReplyNotReboot() {
        let id = UUID()
        let c = RemoteHostController(host: RemoteHost(name: "t", address: "127.0.0.1", port: 1, user: "nobody"))
        var reboots = 0
        c.onWorkspaceRebooted = { _ in reboots += 1 }
        let booted = Date().timeIntervalSince1970 - 3600
        func push(uptime: Int, bootedAt: Double?) {
            var vm: [String: Any] = ["id": id.uuidString, "state": "running", "uptimeSeconds": uptime,
                                     "tabs": [["index": 0, "title": "t", "active": true]]]
            if let bootedAt { vm["bootedAt"] = bootedAt }
            c.applyPushedSnapshot(["workspaces": [["id": id.uuidString, "name": "w", "tool": "claude",
                                                   "authMode": "token", "state": "running"]],
                                   "vms": [vm], "workspacesListed": true])
        }
        push(uptime: 3600, bootedAt: booted)
        // Built 40 s before it arrived: the uptime reads 40 s short.
        push(uptime: 3560, bootedAt: booted)
        #expect(reboots == 0)
        // A real reboot moves the stamp.
        push(uptime: 5, bootedAt: Date().timeIntervalSince1970 - 5)
        #expect(reboots == 1)
    }

    /// Finding (CWE-682): with a stable boot stamp, a late reply or a Mac
    /// that slept (awake-only uptime) still moved the boot date forward —
    /// the dashboard's uptime dropped and the iPad transcript lost
    /// everything before the new date.
    @Test("a stable boot stamp keeps the boot date from moving later")
    @MainActor func stableStampKeepsBootDate() {
        let prev = now.addingTimeInterval(-3600)
        #expect(RemoteHostController.bootTime(prev: prev, derived: prev.addingTimeInterval(1800),
                                              stampMoved: false) == prev)
        #expect(RemoteHostController.bootTime(prev: prev, derived: prev.addingTimeInterval(-2),
                                              stampMoved: false) == prev.addingTimeInterval(-2))
        #expect(RemoteHostController.bootTime(prev: prev, derived: now, stampMoved: true) == now)

        let id = UUID()
        let c = RemoteHostController(host: RemoteHost(name: "t", address: "127.0.0.1", port: 1, user: "nobody"))
        let booted = Date().timeIntervalSince1970 - 7200
        func push(uptime: Int, bootedAt: Double) {
            c.applyPushedSnapshot(["workspaces": [["id": id.uuidString, "name": "w", "tool": "claude",
                                                   "authMode": "token", "state": "running"]],
                                   "vms": [["id": id.uuidString, "state": "running", "uptimeSeconds": uptime,
                                            "bootedAt": bootedAt,
                                            "tabs": [["index": 0, "title": "t", "active": true]]]],
                                   "workspacesListed": true])
        }
        push(uptime: 3600, bootedAt: booted)
        let first = c.bootTimes[id]
        // Slept 30 min (awake-only uptime), or a reply 30 min late.
        push(uptime: 1800, bootedAt: booted)
        #expect(c.bootTimes[id] == first)
        // A real reboot moves it.
        push(uptime: 5, bootedAt: Date().timeIntervalSince1970 - 5)
        #expect(c.bootTimes[id]! > first!.addingTimeInterval(3000))
    }
}
