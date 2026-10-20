import Foundation
import Testing
@testable import bromure_ac

@Suite("Security window: grouped blocks, search keys, history settings")
struct SecurityWindowQoLTests {
    private func block(_ engine: String, _ condition: String, ws: UUID, at t: TimeInterval) -> SecurityTimeline.Event {
        .init(time: Date(timeIntervalSince1970: t), engine: engine, condition: condition, decision: "deny",
              kind: .blocked, profileID: ws)
    }

    @Test("Latest blocks fold repeats into one row: its count, its last time, the workspaces it hit")
    func groups() {
        let a = UUID(), b = UUID()
        var events = (0..<101).map { block("Firewall", "telemetry.example.net:443 tcp", ws: $0 % 2 == 0 ? a : b, at: Double($0)) }
        events.append(block("Firewall", "evil.example:443 tcp", ws: a, at: 50))
        let groups = SecurityOverview.blockGroups(events)
        #expect(groups.count == 2)
        let noisy = groups.first { $0.latest.condition.hasPrefix("telemetry") }!
        #expect(noisy.count == 101)
        #expect(noisy.latest.time == Date(timeIntervalSince1970: 100))
        #expect(noisy.workspaces == [a, b])
        // Newest group first, and a quiet block is still shown.
        #expect(groups.first?.latest.condition.hasPrefix("telemetry") == true)
        #expect(groups.contains { $0.latest.condition.hasPrefix("evil") })
    }

    @Test("A guest-sandbox denial groups and searches by what was tried, not the pid")
    func sandboxKey() {
        let ws = UUID()
        let e1 = block("Guest sandbox", "bash (pid 412) — exec /opt/grok/bin/grok", ws: ws, at: 1)
        let e2 = block("Guest sandbox", "bash (pid 980) — exec /opt/grok/bin/grok ×3", ws: ws, at: 2)
        #expect(e1.searchKey == "exec /opt/grok/bin/grok")
        #expect(e2.searchKey == e1.searchKey)
        #expect(SecurityOverview.blockGroups([e1, e2]).count == 1)
        #expect(block("Firewall", "evil.example:443 tcp", ws: ws, at: 3).searchKey == "evil.example:443 tcp")
    }

    @Test("History settings: unset means 90 days and 24 hours; 0 keeps everything")
    func settings() {
        let d = UserDefaults.standard
        let savedR = d.object(forKey: SecurityTimeline.retentionKey), savedH = d.object(forKey: SecurityTimeline.defaultRangeKey)
        defer {
            if let savedR { d.set(savedR, forKey: SecurityTimeline.retentionKey) } else { d.removeObject(forKey: SecurityTimeline.retentionKey) }
            if let savedH { d.set(savedH, forKey: SecurityTimeline.defaultRangeKey) } else { d.removeObject(forKey: SecurityTimeline.defaultRangeKey) }
        }
        d.removeObject(forKey: SecurityTimeline.retentionKey)
        d.removeObject(forKey: SecurityTimeline.defaultRangeKey)
        #expect(SecurityTimeline.retentionDays == 90)
        #expect(SecurityTimeline.defaultRangeHours == 24)

        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("sec-prune-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let old = dir.appendingPathComponent("2020-01-01.jsonl")
        FileManager.default.createFile(atPath: old.path, contents: Data())
        d.set(0, forKey: SecurityTimeline.retentionKey)
        SecurityTimeline.prune(dir)
        #expect(FileManager.default.fileExists(atPath: old.path))
        d.set(30, forKey: SecurityTimeline.retentionKey)
        SecurityTimeline.prune(dir)
        #expect(!FileManager.default.fileExists(atPath: old.path))
    }
}
