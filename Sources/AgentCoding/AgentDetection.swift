import Foundation

/// Which coding agents a Sidecar's scan found, and which it may call
/// missing — shared with the app so its tests reach it.
///
/// The scan asks the user's login shell (their PATH, as a session starts
/// the agent). At launch that shell was killed on its timeout (a slow
/// .zshrc, an agent's `--version` that hung): no output at all, so every
/// agent read as missing, and every start was refused with "Claude Code
/// isn't installed on this Mac" until the Agents window was opened again.
/// Now each path is printed before its version is asked for, a scan that
/// didn't reach its end never calls anything missing, and a binary in an
/// installer's folder is found without a shell.
enum AgentDetection {
    static let endMarker = "@@END@@"

    /// The login-shell script: per agent its path (`@@P@@id|path@@`) as soon
    /// as it's known, then its version (`@@V@@id|version@@`); `@@END@@` once
    /// it ran to the end. The markers skip whatever the user's rc files print.
    static func script(_ ids: [String], extraBins: [String]) -> String {
        var s = "export PATH=\"$PATH:\(extraBins.joined(separator: ":"))\"; "
        for id in ids {
            s += "p=$(command -v \(id) 2>/dev/null); if [ -n \"$p\" ]; then "
                + "printf '\\n@@P@@%s|%s@@\\n' \(id) \"$p\"; "
                + "v=$(\(id) --version 2>/dev/null </dev/null | head -1 | tr -d '\\r'); "
                + "printf '\\n@@V@@%s|%s@@\\n' \(id) \"$v\"; fi; "
        }
        return s + "printf '\\n\(endMarker)\\n'"
    }

    struct Scan {
        /// id → (path, version line; nil when the version never came).
        var found: [String: (path: String, version: String?)] = [:]
        /// The script ran to its end: what it didn't find isn't there.
        var complete = false
    }

    static func parse(_ stdout: String) -> Scan {
        var scan = Scan()
        for raw in stdout.split(separator: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line == endMarker { scan.complete = true; continue }
            guard line.hasSuffix("@@"), line.count > 7 else { continue }
            let kind = line.prefix(5)
            guard kind == "@@P@@" || kind == "@@V@@" else { continue }
            let body = line.dropFirst(5).dropLast(2).split(separator: "|", maxSplits: 1,
                                                            omittingEmptySubsequences: false).map(String.init)
            guard body.count == 2, !body[0].isEmpty else { continue }
            if kind == "@@P@@" {
                scan.found[body[0]] = (body[1], scan.found[body[0]]?.version)
            } else if let path = scan.found[body[0]]?.path {
                scan.found[body[0]] = (path, body[1])
            }
        }
        return scan
    }

    /// The agents among `ids` with an executable in one of `dirs` ("$HOME"
    /// expanded) — no shell, so nothing to hang.
    static func onDisk(_ ids: [String], dirs: [String], home: String,
                       isExecutable: (String) -> Bool = { FileManager.default.isExecutableFile(atPath: $0) })
        -> [String: String] {
        var out: [String: String] = [:]
        for id in ids {
            for dir in dirs {
                let d = dir.replacingOccurrences(of: "$HOME", with: home)
                guard !d.isEmpty else { continue }
                let path = (d as NSString).appendingPathComponent(id)
                if isExecutable(path) { out[id] = path; break }
            }
        }
        return out
    }

    /// What a scan may call missing: only from a complete one, and only
    /// what neither the shell nor the disk had.
    static func missing(_ ids: [String], scan: Scan, onDisk: [String: String]) -> Set<String> {
        guard scan.complete else { return [] }
        return Set(ids.filter { scan.found[$0] == nil && onDisk[$0] == nil })
    }
}
