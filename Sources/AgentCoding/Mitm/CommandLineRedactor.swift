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
    /// `curl -u user:password`, `-uuser:password`, `--user`, `--proxy-user`
    /// (`mysql -pSECRET` is left alone: `-p` is a port or `mkdir -p` elsewhere).
    /// Short `-u` / `-U` mean user:password only to curl (`rsync -u` is
    /// "update", its `host:path` a remote path; Finding CWE-670, "Command
    /// redaction erases rsync paths, PWD, and token: URLs that are not
    /// secrets"): `userFlagIsCurl` checks the command. The long forms are
    /// always userinfo.
    private static let userFlag = re(#"((?:^|\s)(-u|--user|--proxy-user|-U)(?:\s+|=)?['"]?[^\s:'"]*):[^\s'"]+"#)
    /// The command a flag at `location` belongs to is curl: a word named
    /// `curl` (any path, any case) since the start of its shell segment. The
    /// segment starts after an unquoted, unescaped `;` `&` `|` followed by a
    /// space (or the end), a newline not escaped, `(` or a backtick — never
    /// at `2>&1` / `&>`, a quoted `a;b` or a URL's `a=1&b=2` — so
    /// `bash -c 'curl …'` and `/usr/bin/curl` count and `rsync -u` doesn't.
    /// Erring toward curl only masks more.
    private static func userFlagIsCurl(_ ns: NSString, before location: Int) -> Bool {
        let chars = Array(ns.substring(to: location).unicodeScalars)
        var start = 0
        var quote: Unicode.Scalar? = nil
        var i = 0
        func spaceOrEnd(_ j: Int) -> Bool { j >= chars.count || chars[j] == " " || chars[j] == "\t" || chars[j] == "\n" }
        while i < chars.count {
            let c = chars[i]
            if let q = quote {
                if c == q { quote = nil }
                else if c == "\\", q == "\"" { i += 1 }
            } else if c == "\\" {
                i += 1                                   // escaped: `\&`, a backslash-newline
            } else if c == "'" || c == "\"" {
                quote = c
            } else if c == "\n" || c == "(" || c == "`" {
                start = i + 1
            } else if c == ";" || c == "|" || c == "&" {
                let redirect = c == "&" && ((i > 0 && chars[i - 1] == ">") || (i + 1 < chars.count && chars[i + 1] == ">"))
                if !redirect, spaceOrEnd(i + 1) || (i + 1 < chars.count && (chars[i + 1] == "&" || chars[i + 1] == "|")) {
                    start = i + 1
                }
            }
            i += 1
        }
        let segment = String(String.UnicodeScalarView(chars[min(start, chars.count)...]))
        return segment.split(whereSeparator: { " \t\n'\"()`".contains($0) })
            .contains { ($0.split(separator: "/").last ?? $0).lowercased() == "curl" }
    }

    /// `Authorization: Bearer x`, `X-Api-Key: x`, `Cookie: …`, `*-Token: x`
    private static let header = re(
        #"((?:proxy-)?authorization|x-api-key|api-key|x-auth-token|cookie|x-[a-z0-9-]*-token)(\s*:\s*)((?:bearer|basic|token|digest)\s+)?[^\s'"]+"#)
    /// `--password value`, `--token value`, …
    private static let secretFlag = re(
        #"(--(?:password|passwd|token|secret|api-key|apikey|access-key|secret-key|private-key|auth-token)(?:\s+|=))(['"]?)[^\s'"]+"#)
    /// `PASSWORD=x`, `api_key=x`, `?access_token=x`, `"token": "x"`. The key
    /// is taken whole, and the secret word ends it or a `_`/`-`/`.` follows
    /// (`API_TOKEN_V2`, not `tokens:list`); the shell's own `PWD` / `OLDPWD`
    /// is a directory, not a password (`DB_PWD` still is).
    private static let keyValue = re(
        #"((?<![A-Za-z0-9_.-])(?!(?:old)?pwd['"]?\s*[=:])[A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|credential|private[_-]?key|access[_-]?key)(?:[_.-][A-Za-z0-9_.-]*)?['"]?\s*[=:]\s*)(['"]?)[^\s'"&,}]+"#)

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
        // user:password after -u/--user — the short flag only for curl.
        let uns = out as NSString
        var userMasked = ""
        var at = 0
        for m in userFlag.matches(in: out, range: NSRange(location: 0, length: uns.length)) {
            let flag = uns.substring(with: m.range(at: 2))
            guard flag.hasPrefix("--") || userFlagIsCurl(uns, before: m.range.location) else { continue }
            userMasked += uns.substring(with: NSRange(location: at, length: m.range(at: 1).upperBound - at)) + ":" + mask
            at = m.range.upperBound
        }
        if at > 0 { out = userMasked + uns.substring(from: at) }
        for (rx, template) in [(urlUserinfo, "$1:\(mask)@"),
                               (header, "$1$2$3\(mask)"), (secretFlag, "$1$2\(mask)"),
                               (keyValue, "$1$2\(mask)")] {
            out = rx.stringByReplacingMatches(in: out, range: NSRange(location: 0, length: (out as NSString).length),
                                             withTemplate: template)
        }
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
