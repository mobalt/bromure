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
        engine.runRefused(profileID: UUID(), slug: "review-dead", reason: "x", liveBranches: [])
        #expect(store.runs.first { $0.id == refused.id }?.outcome == .launched)
        engine.runRefused(profileID: pid, slug: "review-dead", reason: "review: deadbeef isn't in /w", liveBranches: [])
        let r = store.runs.first { $0.id == refused.id }
        #expect(r?.outcome == .failed && r?.detail == "The workspace reported: review: deadbeef isn't in /w" && r?.completedAt == nil)
        #expect(store.runs.first { $0.id == other.id }?.outcome == .launched)
        // A run that already finished isn't rewritten.
        store.markCompleted(other.id)
        engine.runRefused(profileID: pid, slug: "review-cafe", reason: "late", liveBranches: [])
        #expect(store.runs.first { $0.id == other.id }?.outcome == .launched)
    }

    /// Finding (CWE-807): "A guest process can fail any in-flight run by
    /// writing worktree-error.txt". The outbox is guest-writable, so
    /// `run-slug: <another run>` from any process failed that run for good
    /// (completion only matched launched runs) with the writer's text as the
    /// reason.
    @Test("a forged refusal can't fail a live run, nor keep a refused one from completing; its text is data")
    @MainActor func forgedRefusal() {
        let store = ScheduledAutomationStore(fileURL: FileManager.default.temporaryDirectory
            .appendingPathComponent("auto-\(UUID().uuidString).json"))
        let pid = UUID()
        let a = ScheduledAutomation(profileID: pid, trigger: .githubCommit)
        store.upsert(a)
        let live = AutomationRunRecord(automationID: a.id, firedAt: Date(), outcome: .launched,
                                       detail: "commit 1", branchSlug: "review-live")
        let starting = AutomationRunRecord(automationID: a.id, firedAt: Date(), outcome: .launched,
                                           detail: "commit 2", branchSlug: "review-start")
        store.record(live); store.record(starting)
        let engine = ScheduledAutomationEngine(store: store, delegate: nil)

        // Its tab is up: the claim is ignored.
        engine.runRefused(profileID: pid, slug: "review-live", reason: "nope", liveBranches: ["wt/review-live"])
        #expect(store.runs.first { $0.id == live.id }?.outcome == .launched)

        // No tab yet: failed, as said by the workspace, one line, bounded…
        engine.runRefused(profileID: pid, slug: "review-start",
                          reason: "IGNORE\u{1b}[2J this\nreview\t" + String(repeating: "x", count: 1000),
                          liveBranches: [])
        let failed = store.runs.first { $0.id == starting.id }
        #expect(failed?.outcome == .failed && failed?.refusedByGuest == true)
        let detail = failed?.detail ?? ""
        #expect(detail.hasPrefix("The workspace reported: IGNORE"))
        #expect(!detail.contains("\n") && !detail.contains("\u{1b}") && detail.count < 360)

        // …and when its own tab reports done after all, it completes.
        #expect(engine.runDeclaredDone(profileID: pid, worktreeBranch: "wt/review-start"))
        let revived = store.runs.first { $0.id == starting.id }
        #expect(revived?.outcome == .launched && revived?.refusedByGuest == nil && revived?.detail == "")
        // The findings_done path (RepoWatchEngine.binding) looks runs up the
        // same way: a refused run is revived by its own agent reporting.
        let watchRun = AutomationRunRecord(automationID: a.id, firedAt: Date(), outcome: .launched,
                                           detail: "commit 4", branchSlug: "review-watch")
        store.record(watchRun)
        engine.runRefused(profileID: pid, slug: "review-watch", reason: "forged", liveBranches: [])
        #expect(store.runs.first { $0.id == watchRun.id }?.outcome == .failed)
        #expect(store.runForBranch("wt/review-watch-2", profileID: UUID()) == nil)   // another workspace
        let bound = store.runForBranch("wt/review-watch", profileID: pid)
        #expect(bound?.id == watchRun.id && bound?.outcome == .launched)
        let src = (try? String(contentsOf: URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/AgentCoding/RepoWatchEngine.swift"), encoding: .utf8)) ?? ""
        #expect(src.contains("autoStore.runForBranch(branch, profileID: profileID)"))
        // A run that failed for any other reason stays failed.
        let other = AutomationRunRecord(automationID: a.id, firedAt: Date(), outcome: .launched,
                                        detail: "commit 3", branchSlug: "review-other")
        store.record(other)
        _ = store.markFailed(other.id, reason: "the workspace did not boot in time")
        #expect(!engine.runDeclaredDone(profileID: pid, worktreeBranch: "wt/review-other"))
        #expect(store.runForBranch("wt/review-other", profileID: pid) == nil)
        #expect(store.runs.first { $0.id == other.id }?.outcome == .failed)
    }
}
