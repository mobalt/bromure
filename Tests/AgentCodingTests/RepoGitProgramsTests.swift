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

    /// Finding (CWE-754): `git lfs install --local` also sets a `process`
    /// filter; switched off it was blank, and a blank process filter that is
    /// `required` failed every status — a clean checkout read as dirty.
    @Test("a local required process filter with no global driver: a clean tree reads clean")
    func requiredProcessFilterKeepsCleanTree() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("rgp-\(UUID().uuidString)").path
        defer { try? FileManager.default.removeItem(atPath: home) }
        let root = home + "/repo", marker = home + "/PWNED", pwn = home + "/pwn.sh"
        let iso = "export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1; "
        _ = sh(iso + "set -e; mkdir -p \(root); printf '#!/bin/sh\\ntouch \(marker)\\ncat\\n' > \(pwn); chmod +x \(pwn); "
               + "cd \(root); git init -q -b main; echo '*.bin filter=lfs' > .gitattributes; echo a > a.bin; "
               + "git add .; git commit -qm a; "
               + "for k in clean smudge process; do git config filter.lfs.$k \(pwn); done; "
               + "git config filter.lfs.required true; touch a.bin")
        #expect(sh(iso + TaskLitter.status("'\(root)'")) == "")
        #expect(sh(iso + CodingTaskEngine.emptyBranchCommand(root: root, branch: "main", parent: "main",
                                                               worktreeDir: root)).contains("EMPTY"))
        // An edit still shows, and the repository's program never ran.
        _ = sh("echo b > \(root)/a.bin")
        #expect(sh(iso + TaskLitter.status("'\(root)'")).contains(" M a.bin"))
        #expect(!FileManager.default.fileExists(atPath: marker))
    }

    /// Finding (CWE-754): with a GLOBAL clean/smudge driver for the filter,
    /// the blank local `process` shadowed it, and `required=false` hid the
    /// failure — `git add` stored raw bytes and reported success. Now the
    /// required filter fails loudly; the repository's program never runs.
    @Test("a blank process over a global clean/smudge driver fails a required filter, never passes raw bytes")
    func blankProcessOverGlobalDriverFails() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("rgq-\(UUID().uuidString)").path
        defer { try? FileManager.default.removeItem(atPath: home) }
        let root = home + "/repo", marker = home + "/PWNED", pwn = home + "/pwn.sh"
        let global = home + "/global.sh", gcfg = home + "/gitconfig"
        let iso = "export GIT_CONFIG_GLOBAL=\(gcfg) GIT_CONFIG_NOSYSTEM=1; "
        _ = sh("set -e; mkdir -p \(root); printf '#!/bin/sh\\ntouch \(marker)\\ncat\\n' > \(pwn); "
               + "printf '#!/bin/sh\\nprintf FILTERED; cat\\n' > \(global); chmod +x \(pwn) \(global); "
               + "printf '[filter \"lfs\"]\\n\\tclean = \(global)\\n\\tsmudge = \(global)\\n\\trequired = true\\n' > \(gcfg); "
               + iso + "cd \(root); git init -q -b main; echo '*.bin filter=lfs' > .gitattributes; "
               + "git add .gitattributes; git commit -qm a; "
               + "for k in clean smudge process; do git config filter.lfs.$k \(pwn); done; "
               + "git config filter.lfs.required true; echo raw > b.bin")
        let add = sh(iso + RepoGitPrograms.off("'\(root)'")
                     + "git -C '\(root)' add b.bin >/dev/null 2>&1 && echo ADDED || echo REFUSED")
        #expect(add.contains("REFUSED"))
        #expect(sh(iso + "git -C '\(root)' ls-files b.bin").isEmpty)
        #expect(!FileManager.default.fileExists(atPath: marker))
        // Review: a user driver git reads through an include, or an
        // includeIf gitdir: matching this repository, counts the same.
        let inc = home + "/included"
        _ = sh("mv \(gcfg) \(inc); printf '[include]\\n\\tpath = \(inc)\\n' > \(gcfg)")
        let viaInclude = sh(iso + RepoGitPrograms.off("'\(root)'")
                            + "git -C '\(root)' add b.bin >/dev/null 2>&1 && echo ADDED || echo REFUSED")
        #expect(viaInclude.contains("REFUSED"))
        // gitdir: matches the resolved path (/var is /private/var here;
        // Foundation's resolvingSymlinksInPath turns it back into /var).
        _ = sh("git -C '\(root)' reset -q; printf '[includeIf \"gitdir:%s/\"]\\n\\tpath = \(inc)\\n' "
               + "\"$(cd '\(root)' && pwd -P)\" > \(gcfg)")
        let viaIncludeIf = sh(iso + RepoGitPrograms.off("'\(root)'")
                              + "git -C '\(root)' add b.bin >/dev/null 2>&1 && echo ADDED || echo REFUSED")
        #expect(viaIncludeIf.contains("REFUSED"))
        // Only a global smudge, under `set -e` (dash): still a user driver.
        _ = sh("git -C '\(root)' reset -q; printf '[filter \"lfs\"]\\n\\tsmudge = \(global)\\n\\trequired = true\\n' > \(gcfg)")
        let smudgeOnly = sh("set -e; " + iso + RepoGitPrograms.off("'\(root)'")
                            + "git -C '\(root)' add b.bin >/dev/null 2>&1 && echo ADDED || echo REFUSED")
        #expect(smudgeOnly.contains("REFUSED"))
        #expect(sh(iso + "git -C '\(root)' ls-files b.bin").isEmpty)
        // With no user driver at all, the blank process still passes through.
        _ = sh("printf '' > \(gcfg)")
        let passthrough = sh(iso + RepoGitPrograms.off("'\(root)'")
                             + "git -C '\(root)' add b.bin >/dev/null 2>&1 && echo ADDED || echo REFUSED")
        #expect(passthrough.contains("ADDED"))
        #expect(!FileManager.default.fileExists(atPath: marker))
    }

    /// Finding: `--ignore-submodules=dirty` hid an edited submodule — the
    /// session list said "no changes yet", Discard said nothing would be
    /// lost, and removing the worktree deleted that work.
    @Test("an edited submodule reads as a change, and its own programs still don't run")
    @MainActor func dirtySubmoduleCounts() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("rgs-\(UUID().uuidString)").path
        defer { try? FileManager.default.removeItem(atPath: home) }
        let root = home + "/.bromure/worktrees/repo/x"
        let marker = home + "/PWNED", pwn = home + "/pwn.sh"
        _ = sh("set -e; mkdir -p \(home)/sub \(root); printf '#!/bin/sh\\ntouch \(marker)\\ncat\\n' > \(pwn); chmod +x \(pwn); "
               + "cd \(home)/sub; git init -q -b main; echo one > f; git add f; git commit -qm one; "
               + "cd \(root); git init -q -b main; echo a > a; git add a; git commit -qm a; "
               + "git -c protocol.file.allow=always submodule -q add \(home)/sub sub; git commit -qm sub")
        // Clean so far.
        func count() -> String {
            sh(WorktreeEntry.guestCommand, home: home).split(separator: "\t").dropFirst(5).first.map(String.init) ?? "?"
        }
        #expect(count() == "0")
        // Edit a tracked file in the submodule, with a clean filter there.
        _ = sh("cd \(root)/sub; echo secret-edit >> f; echo '* filter=evil' > \"$(git rev-parse --git-dir)/info/attributes\"; "
               + "git config filter.evil.clean \(pwn)")
        #expect(count() == "1")
        #expect(sh(TaskLitter.status("'\(root)'")).contains(" M sub"))
        #expect(sh(AgentSessionEngine.changesProbeCommand([(key: "k", path: root, since: Date())])).contains("k\t1"))
        #expect(sh(BranchMergeCommands.mergeScript(root: root, branch: "wt/none", into: "main", sourceDir: root,
                                                   squash: false)).contains("dirty"))
        #expect(!FileManager.default.fileExists(atPath: marker))
    }

    /// Finding (CWE-754): a submodule whose own `git status` fails (here a
    /// truncated index, as a crash mid-write leaves it) printed nothing, so
    /// the checkout read as clean and empty — and Mark done removed it.
    @Test("a submodule whose status fails reads as a change")
    @MainActor func failedSubmoduleStatusCounts() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("rgf-\(UUID().uuidString)").path
        defer { try? FileManager.default.removeItem(atPath: home) }
        let root = home + "/.bromure/worktrees/repo/x"
        _ = sh("set -e; mkdir -p \(home)/sub \(root); "
               + "cd \(home)/sub; git init -q -b main; echo one > f; git add f; git commit -qm one; "
               + "cd \(root); git init -q -b main; echo a > a; git add a; git commit -qm a; "
               + "git -c protocol.file.allow=always submodule -q add \(home)/sub sub; git commit -qm sub")
        #expect(!sh(TaskLitter.status("'\(root)'")).contains("sub"))
        // A tracked edit, then the submodule's index cut short.
        _ = sh("cd \(root)/sub; echo SECRET >> f; i=\"$(git rev-parse --git-dir)/index\"; "
               + "head -c 20 \"$i\" > \"$i.t\"; mv \"$i.t\" \"$i\"")
        #expect(sh("cd \(root)/sub && git status --porcelain >/dev/null 2>&1 || echo failed").contains("failed"))
        #expect(sh(TaskLitter.status("'\(root)'")).contains(" M sub"))
        #expect(sh(AgentSessionEngine.changesProbeCommand([(key: "k", path: root, since: Date())])).contains("k\t1"))
        #expect(sh(BranchMergeCommands.mergeScript(root: root, branch: "wt/none", into: "main", sourceDir: root,
                                                   squash: false)).contains("dirty"))
    }

    /// Finding (CWE-116): `core.quotePath=false` still C-quotes a path
    /// holding `"`, `\\`, a tab or a newline, and the quoted text was looked
    /// for on disk — an edit in such a submodule read as no change at all.
    @Test("an edited submodule whose path git quotes still reads as a change")
    @MainActor func quotedSubmodulePath() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("rgq-\(UUID().uuidString)").path
        defer { try? FileManager.default.removeItem(atPath: home) }
        let root = home + "/.bromure/worktrees/repo/x"
        _ = sh("set -e; mkdir -p \(home)/sub \(root); "
               + "cd \(home)/sub; git init -q -b main; echo one > f; git add f; git commit -qm one; "
               + "cd \(root); git init -q -b main; echo a > a; git add a; git commit -qm a")
        let names = ["quote\"name", "back\\slash", "new\nline", "tab\tbed", "$(touch PWN)"]
        for (i, name) in names.enumerated() {
            let q = BranchMergeCommands.q(name)
            _ = sh("set -e; cd \(root); git clone -q \(home)/sub \(q); "
                   + "git update-index --add --cacheinfo 160000,$(git -C \(q) rev-parse HEAD),\(q); git commit -qm s\(i)")
        }
        #expect(sh(TaskLitter.status("'\(root)'")).isEmpty)
        for name in names {
            let q = BranchMergeCommands.q(name)
            _ = sh("cd \(root)/\(q) && echo SECRET-EDIT >> f")
            let out = sh(TaskLitter.status("'\(root)'"))
            #expect(out.hasPrefix(" M "), "\(name)")
            #expect(sh("cd \(root); " + RepoGitPrograms.dirtySubmodules(".", nul: true)) == " M \(name)\0", "\(name)")
            _ = sh("cd \(root)/\(q) && git checkout -q f")
        }
        #expect(!FileManager.default.fileExists(atPath: root + "/PWN"))
    }

    /// Finding: the same hidden submodule edit passed the checks that gate
    /// `git worktree remove --force` — the landing's dirty-source check
    /// (a merged branch's worktree is removed) and Mark done's empty branch.
    @Test("a task worktree with an edited submodule is neither landed clean nor empty")
    func dirtySubmoduleBlocksRemoval() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("rgw-\(UUID().uuidString)").path
        defer { try? FileManager.default.removeItem(atPath: home) }
        let root = home + "/repo", wt = home + "/wt"
        _ = sh("set -e; mkdir -p \(home)/sub \(root); "
               + "cd \(home)/sub; git init -q -b main; echo one > f; git add f; git commit -qm one; "
               + "cd \(root); git init -q -b main; echo a > a; git add a; git commit -qm a; "
               + "git -c protocol.file.allow=always submodule -q add \(home)/sub sub; git commit -qm sub; "
               + "git worktree add -q -b wt/t \(wt); cd \(wt); git -c protocol.file.allow=always submodule -q update --init")
        let check = { CodingTaskEngine.parseLandingCheck(self.sh(CodingTaskEngine.landingCheckCommand(
            root: root, branch: "wt/t", target: "main", sourceDir: wt, mode: .merge))) }
        let empty = { self.sh(CodingTaskEngine.emptyBranchCommand(root: root, branch: "wt/t", parent: "main",
                                                                  worktreeDir: wt)) }
        // Nothing done: already merged, and empty.
        #expect(check() == .merged)
        #expect(empty().contains("EMPTY"))
        // An uncommitted edit inside the submodule: the agent must commit it.
        _ = sh("echo secret-edit >> \(wt)/sub/f")
        #expect(check() == .dirtySource)
        #expect(!empty().contains("EMPTY"))
    }
}
