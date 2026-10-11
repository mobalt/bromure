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

    /// Finding (CWE-754): a local filter key was blanked, which hid the
    /// user's global driver of the same name (`git lfs install --local`) and
    /// failed a `required` filter — `git status` exited 128 with no output,
    /// which read as a clean tree, and the worktree was discarded as empty.
    @Test("a local required filter: the global one is kept, or cat; a failing status is never clean")
    func requiredFilterKeepsStatus() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("rgf-\(UUID().uuidString)").path
        defer { try? FileManager.default.removeItem(atPath: home) }
        let root = home + "/repo", marker = home + "/PWNED", globalRan = home + "/GLOBAL"
        let pwn = home + "/pwn.sh", global = home + "/global.sh", gcfg = home + "/gitconfig"
        _ = sh("set -e; mkdir -p \(root); "
               + "printf '#!/bin/sh\\ntouch \(marker)\\ncat\\n' > \(pwn); "
               + "printf '#!/bin/sh\\ntouch \(globalRan)\\ncat\\n' > \(global); chmod +x \(pwn) \(global); "
               + "cd \(root); git init -q -b main; echo '*.bin filter=x' > .gitattributes; echo a > a.bin; "
               + "echo p > plain.txt; git add .; git commit -qm a; "
               + "git config filter.x.clean \(pwn); git config filter.x.smudge \(pwn); git config filter.x.required true; "
               // Same size: git has to read (clean) a.bin to tell.
               + "echo c > a.bin; echo q >> plain.txt")
        // No global driver: the local one is cat, the status still reads.
        let bare = sh(TaskLitter.status("'\(root)'"))
        #expect(bare.contains(" M plain.txt") && bare.contains(" M a.bin"))
        #expect(!FileManager.default.fileExists(atPath: marker))
        // A global driver of the same name: that one runs, never the local one.
        _ = sh("printf '[filter \"x\"]\\n\\tclean = \(global)\\n\\tsmudge = \(global)\\n' > \(gcfg)")
        let withGlobal = sh("export GIT_CONFIG_GLOBAL=\(gcfg); " + TaskLitter.status("'\(root)'"))
        #expect(withGlobal.contains(" M plain.txt"))
        #expect(FileManager.default.fileExists(atPath: globalRan))
        #expect(!FileManager.default.fileExists(atPath: marker))
        // A status that fails is not a clean tree, so the worktree isn't "empty".
        _ = sh("echo garbage > \(root)/.git/index")
        #expect(!sh(TaskLitter.status("'\(root)'")).isEmpty)
        #expect(!sh(CodingTaskEngine.emptyBranchCommand(root: root, branch: "main", parent: "main",
                                                         worktreeDir: root)).contains("EMPTY"))
        // A folder that's gone still reads as clean.
        #expect(sh(TaskLitter.status("'\(home)/nope'")).isEmpty)
    }
}
