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
    /// `curl -u user:password`, `-uuser:password`, `--user`, `--proxy-user`,
    /// and `-u` / `-U` closing a cluster of short flags (`-su user:pw`,
    /// `-fsSLu user:pw`, `-sLuuser:pw`: Finding CWE-532, "A curl -u password
    /// clustered with other short flags is stored and uploaded"). Case-
    /// insensitive, so `[a-z]*u` is -u and -U alike.
    /// (`mysql -pSECRET` is left alone: `-p` is a port or `mkdir -p` elsewhere).
    private static let userFlag = re(#"((?:^|\s)(?:-[a-z]*u|--user|--proxy-user)(?:\s+|=)?['"]?[^\s:'"]*):[^\s'"]+"#)
    /// `Authorization: Bearer x`, `X-Api-Key: x`, `Cookie: …`, `*-Token: x`
    private static let header = re(
        #"((?:proxy-)?authorization|x-api-key|api-key|x-auth-token|cookie|x-[a-z0-9-]*-token)(\s*:\s*)((?:bearer|basic|token|digest)\s+)?[^\s'"]+"#)
    /// `--password value`, `--token value`, …
    private static let secretFlag = re(
        #"(--(?:password|passwd|token|secret|api-key|apikey|access-key|secret-key|private-key|auth-token)(?:\s+|=))(['"]?)[^\s'"]+"#)
    /// `PASSWORD=x`, `api_key=x`, `?access_token=x`, `"token": "x"`
    private static let keyValue = re(
        #"([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|credential|private[_-]?key|access[_-]?key)[A-Za-z0-9_.-]*['"]?\s*[=:]\s*)(['"]?)[^\s'"&,}]+"#)

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
        for (rx, template) in [(urlUserinfo, "$1:\(mask)@"), (userFlag, "$1:\(mask)"),
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
