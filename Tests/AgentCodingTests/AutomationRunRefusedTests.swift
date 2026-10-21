import Foundation
import Testing
@testable import bromure_ac

/// Finding (CWE-670): "A review whose base cannot be fetched is recorded as a
/// successful launch". The host recorded the fire as `.launched` when it
/// queued the run; the guest then refused it (its base not in the checkout
/// after fetching origin) with only a worktree-error.txt, so the board showed
/// a green, finished review of a commit no agent opened.
@Suite("Automations: a run the guest refuses is a failed run")
struct AutomationRunRefusedTests {
    @Test("the guest's error names its run on a first line the host strips")
    func split() {
        let (slug, msg) = ACAppDelegate.splitWorktreeError("run-slug: review-abc\nreview: deadbeef isn't in /w, even after fetching origin")
        #expect(slug == "review-abc" && msg.hasPrefix("review: deadbeef"))
        let (none, plain) = ACAppDelegate.splitWorktreeError("merge: conflicts")
        #expect(none == nil && plain == "merge: conflicts")
    }

    @Test("the refused run turns failed with the reason; other runs, and a done one, are left")
    @MainActor func refusedRunFails() {
        let store = ScheduledAutomationStore(fileURL: FileManager.default.temporaryDirectory
            .appendingPathComponent("auto-\(UUID().uuidString).json"))
        let pid = UUID()
        let a = ScheduledAutomation(profileID: pid, trigger: .githubCommit)
        store.upsert(a)
        let refused = AutomationRunRecord(automationID: a.id, firedAt: Date(), outcome: .launched,
                                          detail: "commit deadbeef", branchSlug: "review-dead")
        let other = AutomationRunRecord(automationID: a.id, firedAt: Date(), outcome: .launched,
                                        detail: "commit cafe", branchSlug: "review-cafe")
        store.record(refused); store.record(other)
        let engine = ScheduledAutomationEngine(store: store, delegate: nil)
        // Another workspace's slug of the same name: not this run.
        engine.runRefused(profileID: UUID(), slug: "review-dead", reason: "x")
        #expect(store.runs.first { $0.id == refused.id }?.outcome == .launched)
        engine.runRefused(profileID: pid, slug: "review-dead", reason: "review: deadbeef isn't in /w")
        let r = store.runs.first { $0.id == refused.id }
        #expect(r?.outcome == .failed && r?.detail == "review: deadbeef isn't in /w" && r?.completedAt == nil)
        #expect(store.runs.first { $0.id == other.id }?.outcome == .launched)
        // A run that already finished isn't rewritten.
        store.markCompleted(other.id)
        engine.runRefused(profileID: pid, slug: "review-cafe", reason: "late")
        #expect(store.runs.first { $0.id == other.id }?.outcome == .launched)
    }
}
