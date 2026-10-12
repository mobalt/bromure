import Foundation
import Testing
@testable import bromure_ac

/// Board report: in Code Review › Overview, picking a repository narrowed
/// the pipeline graph but not the "Needs attention" list (nor the recent
/// scans) — another repository's findings and failed runs still showed.
@Suite("Code review overview: one repository")
struct HubOverviewRepoTests {
    private func finding(_ repo: String) -> RepoFinding {
        RepoFinding(watchID: nil, profileID: UUID(), repo: repo, fingerprint: UUID().uuidString,
                    title: "t", severity: .high, cwe: "CWE-1", file: "f", line: 1, summary: "s",
                    evidence: "e", recommendation: "r")
    }

    @Test("findings and runs follow the picked repository; none picked, all of them")
    func filters() {
        let pid = UUID()
        var a = WatchedRepo(repo: "o/a", profileID: pid)
        var b = WatchedRepo(repo: "o/b", profileID: pid)
        let aScan = UUID(), bScan = UUID(), other = UUID()
        a.automationIDs = ["full": aScan]
        b.automationIDs = ["full": bScan]
        let runs = [aScan, bScan, other].map {
            AutomationRunRecord(automationID: $0, firedAt: Date(), outcome: .failed, detail: "", branchSlug: nil)
        }
        #expect(HubOverviewTab.runs(runs, of: "o/a", watches: [a, b]).map(\.automationID) == [aScan])
        #expect(HubOverviewTab.runs(runs, of: nil, watches: [a, b]).count == 3)
        let fs = [finding("o/a"), finding("o/b"), finding("o/a")]
        #expect(HubOverviewTab.findings(fs, of: "o/a").count == 2)
        #expect(HubOverviewTab.findings(fs, of: "o/b").map(\.repo) == ["o/b"])
        #expect(HubOverviewTab.findings(fs, of: nil).count == 3)
    }
}
