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

    /// Finding (CWE-670): the host's schedule zone was stored once at launch.
    /// After the Mac moved zone the editor kept setting hours on the old
    /// clock, while the engine planted fires on the new one — a "9:00" shown
    /// as 9:00 Eastern ran at 9:00 London. The zone is read live, the engine
    /// plants on the editor's calendar, and a zone change replans what's ahead.
    @Test("this Mac's schedule zone is read live; a zone change replans the fires still ahead")
    @MainActor func hostZoneFollowsTheMac() {
        let store = ScheduledAutomationStore(fileURL: FileManager.default.temporaryDirectory
            .appendingPathComponent("tz-\(UUID().uuidString).json"))
        #expect(store.scheduleTimeZone == TimeZone.current)
        let ahead = daily(9), due = daily(10)
        var watch = daily(11), every = daily(12)
        watch.trigger = .githubPullRequest
        every.frequency = .interval
        every.intervalMinutes = 60
        store.upsert(ahead); store.upsert(due); store.upsert(watch); store.upsert(every)
        let later = now.addingTimeInterval(3600), earlier = now.addingTimeInterval(-60)
        func plant() {
            store.setNextFire(later, for: ahead.id)
            store.setNextFire(earlier, for: due.id)
            store.setNextFire(later, for: watch.id)
            store.setNextFire(later, for: every.id)
        }
        func replanned() {
            #expect(store.nextFire(for: ahead.id) == nil)     // replanned on the new clock
            #expect(store.nextFire(for: due.id) == earlier)   // still due: runs (or is skipped as missed)
            #expect(store.nextFire(for: watch.id) == later)   // not a clock schedule
            #expect(store.nextFire(for: every.id) == later)   // an interval keeps its phase
        }
        plant()
        store.systemTimeZoneChanged(now: now)
        replanned()
        // Changed while the app was quit: the engine replans as it starts.
        plant()
        store.replanWallClockFires(now: now)
        replanned()
        #expect(store.scheduleTimeZone == TimeZone.current)

        // A mirror keeps the host's zone, and its planned fires.
        let mirror = ScheduledAutomationStore(fileURL: FileManager.default.temporaryDirectory
            .appendingPathComponent("tz-\(UUID().uuidString).json"))
        let elsewhere = TimeZone.current.secondsFromGMT() == eastern.secondsFromGMT() ? tokyo : eastern
        mirror.mirror(automations: [daily(9)], runs: [], nextFires: [:], timeZone: elsewhere)
        mirror.systemTimeZoneChanged(now: now)
        #expect(mirror.scheduleTimeZone == elsewhere)

        // The engine plants on the schedules' clock — what the editor previews.
        let engine = ScheduledAutomationEngine(store: mirror, delegate: nil)
        let a = daily(9)
        mirror.mirror(automations: [a], runs: [], nextFires: [:], timeZone: elsewhere)
        engine.tick(now: now)
        let planted = mirror.nextFire(for: a.id)
        #expect(planted == AutomationSchedule.nextFire(for: a, after: now, calendar: mirror.scheduleCalendar))
        var cal = Calendar(identifier: .gregorian); cal.timeZone = elsewhere
        #expect(planted.map { cal.component(.hour, from: $0) } == 9)
    }
}
