import Foundation
import IOKit.pwr_mgt
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

    /// Finding (CWE-400): the keep-awake lived as long as the budget object,
    /// which a checkout automation held through its clone (up to 15 min), and
    /// a guest exec that never answered held it for the life of the app.
    @Test("the keep-awake ends when the time is up, checked or not, or on release")
    func keepAwakeEnds() async throws {
        let c = Clock()
        let b = BootBudget(seconds: 180, reason: "test", clock: { c.now })
        #expect(b.holdsAwake)
        c.now += 180
        #expect(!b.remains)
        #expect(!b.holdsAwake)
        // Released early: the workspace answered.
        let r = BootBudget(seconds: 180, reason: "test")
        r.release()
        #expect(!r.holdsAwake)
        r.release()   // idempotent
        // Never checked again (a caller stuck in a call): it still ends.
        let stuck = BootBudget(seconds: 0.2, reason: "test")
        try await Task.sleep(nanoseconds: 600_000_000)
        #expect(!stuck.holdsAwake)
    }

    @Test("a guest that takes the request and never answers can't hold the exchange")
    func exchangeHasADeadline() {
        var fds: [Int32] = [0, 0]
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)
        defer { close(fds[0]); close(fds[1]) }
        let start = ProcessInfo.processInfo.systemUptime
        let out = ACAutomationServer.exchangeJSON(fd: fds[0], request: ["cmd": "true"], replyWithin: 0.3)
        let took = ProcessInfo.processInfo.systemUptime - start
        if case .protocolFailure = out {} else { Issue.record("expected a protocol failure, got \(out)") }
        #expect(took < 3)
    }

    /// Finding: the boot's keep-awake was PreventUserIdleSystemSleep only,
    /// which a dark wake's return to sleep ignores — the boot lost the CPU.
    @Test("the boot holds PreventSystemSleep too, and lets it go with the budget")
    func preventsSystemSleep() {
        let reason = "boot-budget-test-\(UUID().uuidString)"
        func held() -> Bool {
            var dict: Unmanaged<CFDictionary>?
            guard IOPMCopyAssertionsByProcess(&dict) == kIOReturnSuccess,
                  let all = dict?.takeRetainedValue() as? [NSNumber: [[String: Any]]],
                  let mine = all[NSNumber(value: getpid())] else { return false }
            return mine.contains {
                $0[kIOPMAssertionNameKey as String] as? String == reason
                    && $0[kIOPMAssertionTypeKey as String] as? String == kIOPMAssertionTypePreventSystemSleep as String
            }
        }
        let b = BootBudget(seconds: 180, reason: reason)
        #expect(held())
        b.release()
        #expect(!held())
        #expect(!b.holdsAwake)
    }
}
