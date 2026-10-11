import Foundation
import Testing
@testable import bromure_ac

/// Finding (CWE-88): the native sessions' copy of the branch merge and PR
/// commands still passed branch names to git as options, and spliced them
/// raw into a host shell script (a squash commit message) and an awk
/// program (the squash brief). One copy now serves VM and native sessions.
@Suite("Branch merge commands")
struct BranchMergeCommandsTests {
    private func sh(_ c: String, in dir: String) -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/bash")
        p.arguments = ["-c", c]
        p.currentDirectoryURL = URL(fileURLWithPath: dir)
        var env = ProcessInfo.processInfo.environment
        env["GIT_AUTHOR_NAME"] = "t"; env["GIT_AUTHOR_EMAIL"] = "t@t"
        env["GIT_COMMITTER_NAME"] = "t"; env["GIT_COMMITTER_EMAIL"] = "t@t"
        p.environment = env
        let pipe = Pipe(); p.standardOutput = pipe; p.standardError = Pipe()
        try? p.run(); p.waitUntilExit()
        return String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    }

    @Test("an option-shaped name never reaches git: the script and the briefs refuse it")
    func optionShapedRefused() {
        for bad in ["--exec=/tmp/p.sh", "--receive-pack=/tmp/p.sh", "-x"] {
            #expect(BranchMergeCommands.mergeScript(root: "/r", branch: bad, into: "main", sourceDir: "/s",
                                                    squash: true) == "echo conflict")
            #expect(BranchMergeCommands.mergeScript(root: "/r", branch: "wt/x", into: bad, sourceDir: "/s",
                                                    squash: false) == "echo conflict")
            #expect(BranchMergeCommands.unsafeBranch("wt/x", bad) == bad)
        }
        let pr = BranchMergeCommands.pullRequestPrompt(branch: "wt/x", into: "main")
        #expect(pr.contains("`git push -u -- origin 'refs/heads/wt/x'`"))
        #expect(pr.contains("`gh pr create --base 'main'`"))
        let m = BranchMergeCommands.mergePrompt(branch: "wt/x", into: "main", squash: false, why: .conflict)
        #expect(m.contains("`git merge --no-edit -- 'wt/x'`"))
    }

    @Test("a name git accepts that holds shell syntax runs nothing, in the squash script or its brief")
    func shellSyntaxRunsNothing() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("bmc-\(UUID().uuidString)").path
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let marker = dir + "/pwned"
        let evil = "x\";touch${IFS}\(marker);\""
        let evilParent = "y';touch${IFS}\(marker);'"
        #expect(BranchMergeCommands.isSafeBranchName(evil) && BranchMergeCommands.isSafeBranchName(evilParent))
        let root = dir + "/repo", wt = dir + "/wt"
        _ = sh("git init -q -b main repo && cd repo && echo a > a && git add a && git commit -qm a "
               + "&& git worktree add -q -b \(BranchMergeCommands.q(evil)) \(wt) && cd \(wt) "
               + "&& echo b > b && git add b && git commit -qm b", in: dir)
        // git took both names (the repository can carry them).
        #expect(sh("git check-ref-format --branch \(BranchMergeCommands.q(evil))", in: root).contains("touch"))

        let out = sh(BranchMergeCommands.mergeScript(root: root, branch: evil, into: "main", sourceDir: wt,
                                                     squash: true), in: root)
        #expect(out.trimmingCharacters(in: .whitespacesAndNewlines) == "merged")
        #expect(!FileManager.default.fileExists(atPath: marker))
        #expect(sh("git log -1 --format=%s main", in: root).trimmingCharacters(in: .whitespacesAndNewlines)
                == "Squash-merge " + evil)

        // The brief's awk step, as the agent would run it, with a parent
        // whose name closes a single quote.
        _ = sh("git branch \(BranchMergeCommands.q(evilParent)) main", in: root)
        let probe = sh("\(BranchMergeCommands.checkoutOf(evilParent)); echo done", in: root)
        #expect(probe.contains("done"))
        #expect(!FileManager.default.fileExists(atPath: marker))
        #expect(sh(BranchMergeCommands.checkoutOf("main"), in: root).trimmingCharacters(in: .whitespacesAndNewlines)
                .hasSuffix("/repo"))
    }
}
