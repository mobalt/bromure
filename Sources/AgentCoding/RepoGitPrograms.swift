import Foundation

/// The git Bromure runs ITSELF in a task's or a session's repository — a
/// dirty check, a fast-forward, the review's diff, a branch session's merge
/// — runs none of the programs that repository's own config names. The
/// repository is the agent's work, a copied worktree, or a zip with its
/// `.git`: its config is data. (An agent's own git, in its sandbox, is its
/// business.)
///
/// Pinned: hooks (`core.hooksPath`) and `core.fsmonitor`. Switched off:
/// every clean/smudge/process filter and merge driver, and `gpg` program,
/// set in the LOCAL or WORKTREE config (includes count as local) — `git
/// status` runs a clean filter, a checkout or merge a smudge one, on
/// attributes `.git/info/attributes` or an incoming `.gitattributes` can
/// name. The user's own (global, system) drivers — git-lfs — still apply.
/// A diff runs its programs only with `--no-ext-diff --no-textconv` off.
enum RepoGitPrograms {
    /// The config keys whose value is a program git runs on its own.
    static let programKeys = #"^(filter\..*\.(clean|smudge|process)|merge\..*\.driver|gpg\.([^.]*\.)?program)$"#

    /// Shell that sets this shell's git environment (GIT_CONFIG_COUNT/KEY/
    /// VALUE) for every git after it: what `dirs` (already shell-quoted, or
    /// a "$var") configure locally switched off. Names reach git through
    /// the environment, never the command line, so no name is read as an
    /// option or split by the shell.
    static func off(_ dirs: String...) -> String {
        let read = dirs.map { "git -C \($0) config --show-scope --name-only --get-regexp '\(programKeys)'" }
            .joined(separator: "; ")
        return "_bk=$( { \(read); } 2>/dev/null "
            + #"| awk '{ s = $0; sub(/\t.*/, "", s); if (s == "local" || s == "worktree") { sub(/^[^\t]*\t/, ""); print } }'); "#
            + "export GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/dev/null "
            + "GIT_CONFIG_KEY_1=core.fsmonitor GIT_CONFIG_VALUE_1=false; _bn=2; "
            + "set -f; _bo=$IFS; IFS=$(printf '\\n_'); IFS=${IFS%_}; "
            + "for _bx in $_bk; do export \"GIT_CONFIG_KEY_$_bn=$_bx\" \"GIT_CONFIG_VALUE_$_bn=\"; _bn=$((_bn + 1)); done; "
            + "IFS=$_bo; set +f; export GIT_CONFIG_COUNT=$_bn; "
    }

    /// The flags a diff Bromure runs itself carries: no external diff, no
    /// textconv program, no recursion into a submodule (its own config).
    static let diffFlags = "--no-ext-diff --no-textconv --ignore-submodules=dirty"
}
