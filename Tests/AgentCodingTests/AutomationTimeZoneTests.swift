import Foundation
import Testing
@testable import bromure_ac

/// Board report: a 3 AM ET schedule on a US host read "at 3:00" in the
/// editor and "next 16:00" in the sidebar, seen from Japan — neither said
/// which clock. Schedules run on the host's; a viewer elsewhere gets that
/// zone named, and its own time beside it.
@Suite("Automation schedules across time zones")
struct AutomationTimeZoneTests {
    let eastern = TimeZone(identifier: "America/New_York")!
    let tokyo = TimeZone(identifier: "Asia/Tokyo")!
    /// 2026-10-13 12:00 UTC (EDT is UTC-4, Tokyo UTC+9).
    let now = Date(timeIntervalSince1970: 1_791_892_800)

    private func daily(_ hour: Int) -> ScheduledAutomation {
        var a = ScheduledAutomation(profileID: UUID())
        a.trigger = .schedule
        a.frequency = .daily
        a.hour = hour
        a.minute = 0
        return a
    }

    @Test("seen from another zone, the host's time is named and the local one follows")
    func describedAcrossZones() {
        let s = AutomationDescriber.time(daily(3), timeZone: eastern, viewer: tokyo, now: now)
        #expect(s.contains(AutomationDescriber.zoneName(eastern, at: now)))
        #expect(s.contains(AutomationDescriber.zoneName(tokyo, at: now)))
        #expect(s.contains("3") && s.contains("4"))   // 3:00 AM there, 4:00 PM here
        // Same zone: just the time, nothing added.
        let same = AutomationDescriber.time(daily(3), timeZone: tokyo, viewer: tokyo, now: now)
        #expect(!same.contains(AutomationDescriber.zoneName(tokyo, at: now)))
    }

    @Test("a next run shows local time, its zone named when the host runs on another clock")
    func momentNamesZone() {
        let next = Date(timeIntervalSince1970: 1_791_961_200)   // 07:00 UTC = 3:00 EDT = 16:00 JST
        let there = AutomationDescriber.moment(next, scheduleTimeZone: eastern, viewer: tokyo)
        #expect(there.hasSuffix(AutomationDescriber.zoneName(tokyo, at: next)))
        let local = AutomationDescriber.moment(next, scheduleTimeZone: tokyo, viewer: tokyo)
        #expect(!local.hasSuffix(AutomationDescriber.zoneName(tokyo, at: next)))
    }

    @Test("the editor's next-run preview runs on the host's clock, not the viewer's")
    @MainActor func nextFireOnHostClock() {
        let store = ScheduledAutomationStore(fileURL: FileManager.default.temporaryDirectory
            .appendingPathComponent("tz-\(UUID().uuidString).json"))
        store.mirror(automations: [], runs: [], timeZone: eastern)
        #expect(store.scheduleTimeZone == eastern)
        let next = AutomationSchedule.nextFire(for: daily(3), after: now, calendar: store.scheduleCalendar)
        var tokyoCal = Calendar(identifier: .gregorian)
        tokyoCal.timeZone = tokyo
        var eastCal = Calendar(identifier: .gregorian)
        eastCal.timeZone = eastern
        #expect(eastCal.component(.hour, from: next) == 3)
        #expect(tokyoCal.component(.hour, from: next) == 16)
    }

    /// Review: the board card's schedule line ("Daily 3:00") still showed the
    /// host's hour unlabeled.
    @Test("the one-line schedule summary names the host's zone when it isn't the viewer's")
    func summaryNamesZone() {
        let elsewhere = TimeZone.current.secondsFromGMT() == eastern.secondsFromGMT() ? tokyo : eastern
        let s = scheduleSummary(daily(3), timeZone: elsewhere)
        #expect(s.hasSuffix(AutomationDescriber.zoneName(elsewhere, at: Date())))
        #expect(!scheduleSummary(daily(3), timeZone: .current).contains(AutomationDescriber.zoneName(.current, at: Date())))
    }
}
