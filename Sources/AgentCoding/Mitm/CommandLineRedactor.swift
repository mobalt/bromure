import Foundation

/// Secrets in a command line, taken out before it's recorded (the Security
/// Timeline) or uploaded (the org event stream): `net.flow`'s argv and tool
/// command, `tool.use`'s input summary, `command.run`'s command. A key with a
/// known scheme prefix becomes its fingerprint label (`[GitHub token
/// #3f9a1c2e]`, as everywhere else); a password, header value or `--token`
/// argument becomes `***`.
enum CommandLineRedactor {
    static let mask = "***"

    /// Event fields that carry command lines (at any depth: a flow's
    /// `processes[].argv`, its `agent.command`).
    static let commandFields: Set<String> = ["argv", "command", "input_summary", "cmd"]

    private static func re(_ p: String) -> NSRegularExpression {
        try! NSRegularExpression(pattern: p, options: [.caseInsensitive])
    }

    private static let knownTokens = re(
        #"\b(?:sk-ant-[A-Za-z0-9_-]{10,}|sk-(?:proj-|svcacct-|or-)?[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}"#
        + #"|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{16,}|xox[abp]-[A-Za-z0-9-]{10,}|xapp-[A-Za-z0-9-]{10,}"#
        + #"|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|hf_[A-Za-z0-9]{20,}|npm_[A-Za-z0-9]{20,}"#
        + #"|pypi-[A-Za-z0-9_-]{20,}|dop_v1_[a-f0-9]{20,}|xai-[A-Za-z0-9]{20,}|gsk_[A-Za-z0-9]{20,}"#
        + #"|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,})"#)
    /// `scheme://user:password@host`
    private static let urlUserinfo = re(#"([a-z][a-z0-9+.-]*://[^/\s:@'"]+):[^@\s/'"]+@"#)

    // Each pattern below matches up to where its value starts, with the
    // value's opening quote (if any) in group 2; `value(…)` then takes the
    // value itself: a quoted one through its matching quote, spaces and all,
    // an unquoted one up to a space or quote (Finding CWE-532: "Cookie flags
    // and secrets past the first space are still stored and uploaded" — a
    // value stopped at the first space, so `-u "alice:my hunter2"` kept
    // "hunter2" and a Cookie header kept every pair after the first).

    /// `curl -u user:password`, `-uuser:password`, `--user`, `--proxy-user`
    /// (`mysql -pSECRET` is left alone: `-p` is a port or `mkdir -p` elsewhere).
    private static let userFlag = re(#"((?:^|\s)(?:-u|--user|--proxy-user|-U)(?:\s+|=)?)(['"]?)"#)
    /// curl's `-b` / `--cookie name=value; …` (a value without `=` is a
    /// cookie file, and `-b` is `git checkout -b`'s branch: both kept;
    /// `--cookie-jar` is a path).
    private static let cookieFlag = re(#"((?:^|\s)(?:-b(?:\s+|=)?|--cookie(?:\s+|=)))(['"]?)"#)
    /// `Authorization: Bearer x`, `X-Api-Key: x`, `Cookie: …`, `*-Token: x`.
    /// Group 2 is the quote opening the whole header argument
    /// (`-H 'Cookie: a=1; b=2'`): the value runs to its match.
    private static let header = re(
        #"()(['"]?)((?:proxy-)?authorization|x-api-key|api-key|x-auth-token|cookie|x-[a-z0-9-]*-token)(\s*:\s*)((?:bearer|basic|token|digest)\s+)?"#)
    /// `--password value`, `--token value`, …
    private static let secretFlag = re(
        #"(--(?:password|passwd|token|secret|api-key|apikey|access-key|secret-key|private-key|auth-token)(?:\s+|=))(['"]?)"#)
    /// `PASSWORD=x`, `api_key=x`, `?access_token=x`, `"token": "x"`
    private static let keyValue = re(
        #"([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|credential|private[_-]?key|access[_-]?key)[A-Za-z0-9_.-]*['"]?\s*[=:]\s*)(['"]?)"#)

    /// The value starting at `start` (UTF-16): through the matching `quote`
    /// when there is one (to the end if it's never closed), else while no
    /// space, quote or `stops` character comes; an unquoted cookie value
    /// goes on across its `; name=value` pairs (the sentry's argv is the
    /// process's arguments joined by spaces, its quotes gone).
    private static func valueEnd(_ ns: NSString, from start: Int, quote: String, stops: String,
                                 cookiePairs: Bool = false) -> Int {
        let n = ns.length
        if !quote.isEmpty {
            let q = ns.range(of: quote, options: [], range: NSRange(location: start, length: n - start))
            return q.location == NSNotFound ? n : q.location
        }
        let stop = CharacterSet.whitespacesAndNewlines.union(CharacterSet(charactersIn: "'\"" + stops))
        func run(_ i: Int) -> Int {
            var j = i
            while j < n, let u = UnicodeScalar(ns.character(at: j)), !stop.contains(u) { j += 1 }
            return j
        }
        var end = run(start)
        while cookiePairs, end > start, end < n, ns.character(at: end - 1) == 0x3B /* ; */ {
            var k = end
            while k < n, ns.character(at: k) == 0x20 { k += 1 }
            let next = run(k)
            guard next > k, ns.substring(with: NSRange(location: k, length: next - k)).contains("=") else { break }
            end = next
        }
        return end
    }

    /// Every match of `rx`, its value (see `valueEnd`) replaced by what
    /// `masked(value)` returns (nil = left as is). The prefix (all groups
    /// but the value) is kept.
    private static func replacingValues(_ s: String, _ rx: NSRegularExpression, stops: String = "",
                                        cookiePairs: (NSTextCheckingResult, NSString) -> Bool = { _, _ in false },
                                        masked: (String) -> String?) -> String {
        let ns = s as NSString
        var out = ""
        var pos = 0
        // Resumed after each value: `^` and `\s` still see the whole string.
        while pos < ns.length,
              let m = rx.firstMatch(in: s, options: [.withoutAnchoringBounds, .withTransparentBounds],
                                    range: NSRange(location: pos, length: ns.length - pos)) {
            let start = m.range.location + m.range.length
            let q = m.range(at: 2)
            let quote = q.location == NSNotFound || q.length == 0 ? "" : ns.substring(with: q)
            let end = valueEnd(ns, from: start, quote: quote, stops: stops, cookiePairs: cookiePairs(m, ns))
            out += ns.substring(with: NSRange(location: pos, length: start - pos))
            let value = ns.substring(with: NSRange(location: start, length: end - start))
            out += value.isEmpty ? "" : (masked(value) ?? value)
            pos = end
        }
        if pos < ns.length { out += ns.substring(from: pos) }
        return out
    }

    static func redact(_ s: String) -> String {
        guard !s.isEmpty else { return s }
        var out = s
        // Known schemes first: their label keeps rows correlatable.
        let ns = out as NSString
        var labelled = ""
        var last = 0
        for m in knownTokens.matches(in: out, range: NSRange(location: 0, length: ns.length)) {
            labelled += ns.substring(with: NSRange(location: last, length: m.range.location - last))
            labelled += "[\(SecretFingerprint.label(ns.substring(with: m.range)))]"
            last = m.range.location + m.range.length
        }
        if last > 0 { out = labelled + ns.substring(from: last) }
        out = urlUserinfo.stringByReplacingMatches(in: out, range: NSRange(location: 0, length: (out as NSString).length),
                                                   withTemplate: "$1:\(mask)@")
        // user:password — the user stays.
        out = replacingValues(out, userFlag) { v in
            v.firstIndex(of: ":").map { String(v[..<$0]) + ":" + mask }
        }
        out = replacingValues(out, cookieFlag, cookiePairs: { _, _ in true }) { $0.contains("=") ? mask : nil }
        out = replacingValues(out, header, cookiePairs: { m, ns in
            ns.substring(with: m.range(at: 3)).lowercased() == "cookie"
        }) { _ in mask }
        out = replacingValues(out, secretFlag) { _ in mask }
        out = replacingValues(out, keyValue, stops: "&,}") { _ in mask }
        return out
    }

    /// An event's data with every command-line field redacted, at any depth.
    static func scrub(_ data: [String: AnyJSON]) -> [String: AnyJSON] {
        var out = data
        for (k, v) in data { out[k] = scrub(v, commandField: commandFields.contains(k)) }
        return out
    }

    private static func scrub(_ v: AnyJSON, commandField: Bool) -> AnyJSON {
        switch v {
        case .string(let s): return commandField ? .string(redact(s)) : v
        case .array(let a): return .array(a.map { scrub($0, commandField: commandField) })
        case .object(let o):
            var r: [String: AnyJSON] = [:]
            for (k, x) in o { r[k] = scrub(x, commandField: commandField || commandFields.contains(k)) }
            return .object(r)
        default: return v
        }
    }
}
