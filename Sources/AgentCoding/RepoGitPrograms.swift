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
/// name. The user's own (global, system) drivers — git-lfs — still apply,
/// even where the local config sets the same key (`git lfs install
/// --local`): such a key is pinned to the global/system value. With none, a
/// filter's clean/smudge becomes `cat` — never blank, which fails a
/// `filter.<x>.required` filter and with it `git status` and the merge.
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
            + "for _bx in $_bk; do "
            + #"_bv=$(cd / && { git config --global --get "$_bx" || git config --system --get "$_bx"; } 2>/dev/null) "#
            + "|| case \"$_bx\" in (filter.*.clean|filter.*.smudge) _bv=cat ;; (*) _bv= ;; esac; "
            + "export \"GIT_CONFIG_KEY_$_bn=$_bx\" \"GIT_CONFIG_VALUE_$_bn=$_bv\"; _bn=$((_bn + 1)); done; "
            + "IFS=$_bo; set +f; export GIT_CONFIG_COUNT=$_bn; "
    }

    /// Appended to a `git status --porcelain` Bromure reads as "dirty or
    /// clean": a status that FAILS prints this line, so a failure is never
    /// the empty output a clean tree gives (which let a worktree holding
    /// edits be discarded as empty).
    static let statusFailed = " || echo '!! (git status failed)'"

    /// Shell printing ` M <path>` (NUL-ended with `nul`, else newline-ended)
    /// for every checked-out submodule under `dir` (already shell-quoted, or
    /// a "$var") with uncommitted work, nested ones included. Bromure's
    /// statuses pass `--ignore-submodules=dirty`, so git never reads a
    /// submodule under the PARENT's switched-off programs — which hid an
    /// edited submodule: the checkout read as clean ("nothing is lost") and
    /// discarding it deleted that work. Each submodule's status runs in the
    /// submodule, under its own `off`; one that fails (a truncated index, an
    /// unknown repository extension) counts as dirty, as `statusFailed` does
    /// for the parent — never the empty output of a clean submodule. Paths
    /// are relative to `dir`.
    static func dirtySubmodules(_ dir: String, nul: Bool = false) -> String {
        let end = nul ? "\\0" : "\\n"
        return "_bsl() { git -c core.quotePath=false -C \"$1\" ls-files --stage 2>/dev/null "
            + "| awk -F'\\t' '$1 ~ /^160000 /{print $2}'; }; "
            + "_bsd() { [ -n \"$( ( cd \"$1\" || { echo '!!'; exit; }; \(off("."))git status --porcelain --ignore-submodules=dirty\(statusFailed) ) 2>/dev/null | head -c1)\" ] "
            + "&& return 0; _bsl \"$1\" | { while IFS= read -r _s; do [ -e \"$1/$_s/.git\" ] && _bsd \"$1/$_s\" && exit 0; done; exit 1; }; }; "
            + "_bsl \(dir) | while IFS= read -r _s; do [ -e \(dir)/\"$_s/.git\" ] && _bsd \(dir)/\"$_s\" "
            + "&& printf ' M %s\(end)' \"$_s\"; done; "
    }

    /// The flags a diff Bromure runs itself carries: no external diff, no
    /// textconv program, no recursion into a submodule (its own config).
    static let diffFlags = "--no-ext-diff --no-textconv --ignore-submodules=dirty"
}
