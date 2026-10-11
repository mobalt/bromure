import Foundation
import Testing
@testable import bromure_ac

/// Finding (CWE-362): Delete workspace (and reset / revert) checked only
/// `runningSessions`, which a boot enters at `registerSession` — after the
/// disk is cloned, prepared and opened. A delete in that window removed the
/// images under the booting VM.
@Suite("A booting workspace's disk is in use")
@MainActor struct BootsInFlightTests {
    @Test("from launch until the boot registers or fails, the disk is in use and a second boot is refused")
    func bootWindow() {
        let boots = BootsInFlight()
        let id = UUID(), other = UUID()
        #expect(!boots.diskInUse(id, running: false))
        #expect(boots.begin(id))
        // Not yet in runningSessions, but booting: delete/reset/revert refuse.
        #expect(boots.diskInUse(id, running: false))
        #expect(boots.contains(id))
        #expect(!boots.begin(id))
        #expect(!boots.diskInUse(other, running: false))
        // Registered (or failed): the boot's mark goes; a running VM still holds it.
        boots.end(id)
        #expect(boots.diskInUse(id, running: true))
        #expect(!boots.diskInUse(id, running: false))
        #expect(boots.begin(id))
    }

    /// Finding (CWE-362): the base-image upgrade and compromise-wipe prompts
    /// are modals, and a boot (an automation's timer) can begin inside one.
    /// "Yes, upgrade" then deleted the disk that boot had just opened.
    @Test("a reset or wipe answered after a boot began does nothing")
    func promptAnsweredAfterBootBegan() {
        // A fresh id: the store's paths for it don't exist, so nothing real
        // is touched either way.
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("boots-\(UUID().uuidString)", isDirectory: true)
        let delegate = ACAppDelegate(
            imageManager: UbuntuImageManager(storageDir: tmp, setupDir: tmp), headless: true)
        var p = Profile(name: "w", tool: .claude, authMode: .token)
        #expect(delegate.bootsInFlight.begin(p.id))
        #expect(!delegate.applyBaseImageUpgradeAnswer(0, profile: &p, current: "999"))
        #expect(!delegate.applyBaseImageUpgradeAnswer(1, profile: &p, current: "999"))
        #expect(p.baseImageUpgradeDeclinedFor == nil)
        #expect(!delegate.wipeCompromised(profile: p))
        // Once that boot is over, the answer applies.
        delegate.bootsInFlight.end(p.id)
        #expect(delegate.applyBaseImageUpgradeAnswer(1, profile: &p, current: "999"))
        #expect(p.baseImageUpgradeDeclinedFor == "999")
    }
}
