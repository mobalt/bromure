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
}
