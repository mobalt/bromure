import Foundation
import Testing
@testable import bromure_ac

/// Finding (CWE-78): the review's git status and diff — and the other
/// status/diff probes Bromure runs itself (the file pane, the session list,
/// the changes probe) — ran programs the repository's own config names:
/// `core.fsmonitor` on a status, `diff.external` / a textconv on a diff.
@Suite("Bromure's own git runs no program the repository names")
struct RepoGitProgramsTests {
    private func sh(_ c: String, home: String? = nil) -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/bash")
        p.arguments = ["-c", c]
        var env = ProcessInfo.processInfo.environment
        env["GIT_AUTHOR_NAME"] = "t"; env["GIT_AUTHOR_EMAIL"] = "t@t"
        env["GIT_COMMITTER_NAME"] = "t"; env["GIT_COMMITTER_EMAIL"] = "t@t"
        if let home { env["HOME"] = home }
        p.environment = env
        let out = Pipe(); p.standardOutput = out; p.standardError = Pipe()
        try? p.run(); p.waitUntilExit()
        return String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    }

    @Test("the review, the session list and the changes probe run no fsmonitor, diff program or filter")
    @MainActor func noRepoPrograms() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("rgp-\(UUID().uuidString)").path
        defer { try? FileManager.default.removeItem(atPath: home) }
        let root = home + "/.bromure/worktrees/repo/x"   // where the session list looks
        let marker = home + "/PWNED", pwn = home + "/pwn.sh"
        _ = sh("set -e; mkdir -p \(root); printf '#!/bin/sh\\ntouch \(marker)\\ncat\\n' > \(pwn); chmod +x \(pwn); "
               + "cd \(root); git init -q -b main; echo a > a; git add a; git commit -qm a; echo b >> a; "
               + "echo '* diff=evil filter=evil' > .git/info/attributes; "
               + "git config core.fsmonitor \(pwn); git config diff.external \(pwn); "
               + "git config diff.evil.textconv \(pwn); git config diff.evil.command \(pwn); "
               + "git config filter.evil.clean \(pwn); git config filter.evil.smudge \(pwn)")
        // The setup is live: plain git runs it.
        _ = sh("cd \(root) && git status --porcelain >/dev/null; true")
        #expect(FileManager.default.fileExists(atPath: marker))
        try FileManager.default.removeItem(atPath: marker)

        let review = sh(TaskReviewData.sessionCommand(dir: root, base: .uncommitted))
        #expect(review.contains("===STATUS===") && review.contains("+b"))
        _ = sh(TaskReviewSummary.command(root: root, worktreeDir: root, branch: "main", target: "main"))
        _ = sh(AgentSessionEngine.changesProbeCommand([(key: "k", path: root, since: Date())]))
        let roster = sh(WorktreeEntry.guestCommand, home: home)
        #expect(roster.contains(root))
        #expect(!FileManager.default.fileExists(atPath: marker))
    }
}
