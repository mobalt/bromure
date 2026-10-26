import Foundation
import Testing
@testable import bromure_ac

/// Finding (CWE-667): "A reboot's lease pin never lapses if the clock steps
/// backward". The pin's deadline was a wall-clock Date, judged after a
/// monotonic sleep: set the clock back past the sleep's 1 s of slack and the
/// wake found the pin "live", did nothing, and nothing ran again -- the lease
/// stayed until the process quit, and the other Bromure process refused the
/// workspace. Deadline and sleep now share ContinuousClock.
@Suite("Reboot lease pins lapse on the clock they sleep on")
struct LeasePinClockTests {
    @Test("live until its deadline, lapsed after; the wake clears only its own pin")
    func lifecycle() {
        var pins = LeasePins()
        let id = UUID(), t0 = ContinuousClock.now
        let d1 = pins.pin(id, for: 600, now: t0)
        #expect(pins.isLive(id, now: t0))
        #expect(pins.isLive(id, now: t0.advanced(by: .seconds(599))))
        #expect(!pins.isLive(id, now: t0.advanced(by: .seconds(600))))
        // The wake at its deadline: the pin is still this one, so it goes.
        let firstWake = pins.lapse(id, deadline: d1)
        #expect(firstWake)
        #expect(!pins.isLive(id, now: t0))
        // A re-pin (a second reboot) outlives the first wake.
        let d2 = pins.pin(id, for: 600, now: t0.advanced(by: .seconds(10)))
        let staleWake = pins.lapse(id, deadline: d1)
        #expect(!staleWake)
        #expect(pins.isLive(id, now: t0.advanced(by: .seconds(11))))
        // A boot's acquire takes it over: its wake does nothing.
        pins.clear(id)
        let takenOverWake = pins.lapse(id, deadline: d2)
        #expect(!takenOverWake)
        #expect(!pins.isLive(id))
    }

    @Test("no wall clock left in the pin: the deadline and the wake's sleep are one clock")
    func oneClock() throws {
        let src = try String(contentsOf: URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/AgentCoding/BromureAC.swift"), encoding: .utf8)
        let start = try #require(src.range(of: "    func releaseLeaseIfIdle(_ id: Profile.ID) {"))
        let end = try #require(src.range(of: "    func unpinLease(_ id: Profile.ID) {", range: start.upperBound..<src.endIndex))
        let pinCode = src[start.lowerBound..<end.lowerBound]
        #expect(!pinCode.contains("Date()"))
        #expect(pinCode.contains("Task.sleep(until: until, clock: .continuous)"))
        #expect(pinCode.contains("leasePins.lapse(id, deadline: until)"))
    }
}
