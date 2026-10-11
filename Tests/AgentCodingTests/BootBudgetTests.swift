import Foundation
import Testing
@testable import bromure_ac

/// An automation on a sleeping Mac: the boot wait counts awake time only.
@Suite("Boot budget")
struct BootBudgetTests {
    final class Clock: @unchecked Sendable { var now: TimeInterval = 1000 }

    @Test("time asleep isn't spent: only the clock that stops in sleep counts")
    func awakeTimeOnly() {
        let c = Clock()
        let b = BootBudget(seconds: 180, reason: "test", holdAwake: false, clock: { c.now })
        #expect(b.remains)
        c.now += 179
        #expect(b.remains)
        c.now += 1
        #expect(!b.remains)
    }

    @Test("the default clock is the one that stops while the Mac sleeps")
    func defaultClock() {
        let b = BootBudget(seconds: 60, reason: "test")
        #expect(b.remains)
    }
}
