import Foundation

/// Thin client for socket.dev's REST API. Looks up package issues
/// keyed by (ecosystem, package, version) and reports two distinct
/// categories the proxy filters on:
///   - `supplyChainRisk`: rogue install scripts, malware-flagged,
///     typosquats, suspicious telemetry, sketchy network access at
///     install time.
///   - `vulnerability`: known CVEs / GHSAs.
///
/// API authentication: HTTP Basic auth with the API key as the
/// username and an empty password (socket.dev's documented scheme
/// for the REST API).
public actor SocketDevClient {
    public enum Severity: String, Sendable {
        case low, middle, high, critical, unknown

        public static func from(string s: String) -> Severity {
            switch s.lowercased() {
            case "low":      return .low
            case "middle", "medium": return .middle
            case "high":     return .high
            case "critical": return .critical
            default:         return .unknown
            }
        }

        public var rank: Int {
            switch self {
            case .low:      return 0
            case .middle:   return 1
            case .high:     return 2
            case .critical: return 3
            case .unknown:  return -1
            }
        }
    }

    public struct Issue: Sendable {
        public let type: String      // socket.dev category identifier
        public let severity: Severity
        public let summary: String   // short human-readable
    }

    public struct CheckResult: Sendable {
        public let compromised: [Issue]   // supplyChainRisk bucket
        public let vulnerabilities: [Issue]  // CVE bucket
    }

    private struct CacheKey: Hashable {
        let ecosystem: String
        let name: String
        let version: String
    }

    private var cache: [CacheKey: CheckResult] = [:]
    private static let cacheCap = 10_000

    // Cap concurrent in-flight calls to socket.dev. The number is a
    // balance: too low starves a big install graph (each tarball
    // waits for a slot, install becomes serial); too high triggers
    // socket.dev rate-limiting and timeouts. 16 keeps a 50-package
    // transitive graph moving without overwhelming the API.
    private static let maxParallel = 16
    /// Total attempts (initial + retries) on transient network
    /// errors. Linear backoff between attempts.
    private static let maxRetries = 5
    private var inFlight = 0
    private var waiters: [CheckedContinuation<Void, Never>] = []

    private func acquireSlot() async {
        while inFlight >= Self.maxParallel {
            await withCheckedContinuation { c in
                waiters.append(c)
            }
        }
        inFlight += 1
    }

    private func releaseSlot() {
        inFlight -= 1
        if !waiters.isEmpty {
            waiters.removeFirst().resume()
        }
    }

    private let session: URLSession

    public init() {
        let cfg = URLSessionConfiguration.ephemeral
        // Be generous on timeouts — socket.dev computes analysis
        // on-demand for less-popular packages on first lookup. A
        // stuck install is more disruptive than a slow check.
        cfg.timeoutIntervalForRequest = 30
        cfg.timeoutIntervalForResource = 60
        // We self-throttle to maxParallel above, so the URLSession's
        // per-host cap need not be high. Leave at the default.
        self.session = URLSession(configuration: cfg)
    }

    /// socket.dev path component for an ecosystem; nil = unsupported.
    public static func socketEcosystem(_ e: String) -> String? {
        switch e {
        case "npm":       return "npm"
        case "pypi":      return "pypi"
        case "go":        return "golang"
        case "maven":     return "maven"
        case "rubygems":  return "rubygems"
        case "nuget":     return "nuget"
        case "packagist": return "packagist"
        default:          return nil
        }
    }

    /// socket.dev issue types that we treat as definitively
    /// malicious — block on any severity. These are the named
    /// "this thing is bad" signals, not quality/attribute metadata.
    private static let alwaysBlockTypes: Set<String> = [
        "malware",
        "knownMalware",
        "gptMalware",
        "troll",
        "compromisedSSHKey",
    ]

    /// socket.dev issue types that smell like an attack but also
    /// fire on legitimate packages at low/middle severity. We block
    /// only when socket.dev itself rates them high or critical.
    /// Example: `installScripts` fires on every package with a
    /// postinstall hook (severity low/middle); a *suspicious*
    /// postinstall is rated high.
    private static let highSeverityBlockTypes: Set<String> = [
        "obfuscatedFile",
        "obfuscatedRequire",
        "suspiciousString",
        "installScripts",
        "gptSecurity",
        "typeSquatting",
        "didYouMean",
        "shellAccess",
        "unusualHTTPS",
        "criticalCVE",
    ]

    /// Issue types we deliberately do NOT treat as compromise
    /// signals, even though socket.dev classifies them under
    /// "supplyChainRisk". Listed for documentation; the loop below
    /// drops anything not in the two sets above.
    ///   newAuthor, envVars, networkAccess, filesystemAccess,
    ///   telemetry, unstableOwnership, newAuthor, deprecated,
    ///   suspiciousStarActivity, hasNativeCode,
    ///   potentialVulnerability
    /// These describe what a package does or who publishes it —
    /// signal for human review, not a programmatic block.

    /// Issue-type prefixes that socket.dev classifies as known CVE.
    private static let cveTypes: Set<String> = [
        "cve", "highCVE", "mediumCVE", "lowCVE", "criticalCVE",
        "vulnerableDependency",
    ]

    /// Sorts socket.dev's issues into the two buckets the proxy filters on.
    static func classify(_ issues: [Issue]) -> CheckResult {
        var compromised: [Issue] = []
        var vulns: [Issue] = []
        let highBar = Severity.high.rank
        for issue in issues {
            let type = issue.type
            // CVE bucket: anything in cveTypes OR a string match on
            // "cve" — the CVE check applies its own severity gate.
            if Self.cveTypes.contains(type) || type.lowercased().contains("cve") {
                vulns.append(issue)
                continue
            }
            // Compromise bucket: only fires for actual attack-shaped
            // types. Quality/attribute signals (newAuthor, envVars,
            // networkAccess, filesystemAccess, …) deliberately don't
            // count, since they describe what most legitimate
            // packages do.
            if Self.alwaysBlockTypes.contains(type) {
                compromised.append(issue)
            } else if Self.highSeverityBlockTypes.contains(type),
                      issue.severity.rank >= highBar {
                compromised.append(issue)
            }
        }
        return CheckResult(compromised: compromised, vulnerabilities: vulns)
    }

    public func check(ecosystem: String, name: String, version: String,
                      apiKey: String) async -> CheckResult? {
        if apiKey.isEmpty { return nil }
        let key = CacheKey(ecosystem: ecosystem,
                            name: name.lowercased(),
                            version: version)
        if let cached = cache[key] { return cached }

        // Only npm has the per-package `issues` route: every other
        // ecosystem got "API route not found" (404), so every PyPI, Go,
        // Maven… install read as "couldn't reach socket.dev" and asked.
        // Those go through the package-URL lookup instead.
        if ecosystem != "npm" {
            guard let purl = Self.purl(ecosystem: ecosystem, name: name, version: version) else { return nil }
            guard let result = await checkPURL(purl, label: "\(ecosystem)/\(name)@\(version)", apiKey: apiKey)
            else { return nil }
            remember(key, result)
            return result
        }
        guard let eco = Self.socketEcosystem(ecosystem) else { return nil }
        // URL-encode the package name (npm scoped packages contain
        // `/` which must be percent-encoded).
        guard let encName = name.addingPercentEncoding(
                withAllowedCharacters: .urlPathAllowed)?
                .replacingOccurrences(of: "/", with: "%2F"),
              let encVer = version.addingPercentEncoding(
                withAllowedCharacters: .urlPathAllowed)
        else { return nil }
        let urlStr = "https://api.socket.dev/v0/\(eco)/\(encName)/\(encVer)/issues"
        guard let url = URL(string: urlStr) else { return nil }

        var req = URLRequest(url: url)
        req.httpMethod = "GET"
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        req.setValue("bromure-ac/2.0", forHTTPHeaderField: "User-Agent")
        // Basic auth: key as username, empty password.
        let basic = "\(apiKey):".data(using: .utf8)!.base64EncodedString()
        req.setValue("Basic \(basic)", forHTTPHeaderField: "Authorization")

        // Throttle: at most maxParallel checks in flight. Cache
        // hits above don't consume a slot.
        await acquireSlot()
        defer { releaseSlot() }

        SupplyChainLog.shared.record("[socket.dev] →  GET \(urlStr)")
        var response: (Data, URLResponse)?
        var lastError: Error?
        for attempt in 1...Self.maxRetries {
            do {
                response = try await session.data(for: req)
                lastError = nil
                break
            } catch {
                lastError = error
                // Only retry on transient network errors; surface
                // everything else (bad URL, cancelled, etc.) on the
                // first try.
                let urlErr = error as? URLError
                let retriable: Bool = {
                    guard let urlErr else { return false }
                    switch urlErr.code {
                    case .timedOut, .networkConnectionLost,
                         .cannotConnectToHost, .dnsLookupFailed,
                         .resourceUnavailable:
                        return true
                    default:
                        return false
                    }
                }()
                if !retriable || attempt == Self.maxRetries { break }
                SupplyChainLog.shared.record(
                    "[socket.dev] ↻  \(ecosystem)/\(name)@\(version) — retry \(attempt)/\(Self.maxRetries - 1) after \(error.localizedDescription)")
                try? await Task.sleep(nanoseconds: UInt64(attempt) * 250_000_000)
            }
        }
        guard let response else {
            let msg = lastError?.localizedDescription ?? "unknown"
            SupplyChainLog.shared.record(
                "[socket.dev] ✗  \(ecosystem)/\(name)@\(version) — network error after retries: \(msg)")
            return nil
        }
        let (data, resp) = response
        let http = resp as? HTTPURLResponse
        let status = http?.statusCode ?? 0
        if status != 200 {
            // Surface auth errors etc. explicitly so a typo'd API
            // key doesn't fail silently. socket.dev returns JSON
            // error bodies for auth failures; include the first
            // 200 bytes of the body for the user to copy.
            let bodyPreview = String(data: data.prefix(200), encoding: .utf8) ?? ""
            SupplyChainLog.shared.record(
                "[socket.dev] ✗  \(ecosystem)/\(name)@\(version) — HTTP \(status): \(bodyPreview)")
            return nil
        }
        guard let arr = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
            SupplyChainLog.shared.record(
                "[socket.dev] ✗  \(ecosystem)/\(name)@\(version) — couldn't parse response JSON")
            return nil
        }

        let result = Self.classify(arr.map { entry in
            let value = entry["value"] as? [String: Any]
            let type = (entry["type"] as? String) ?? ""
            return Issue(type: type,
                         severity: Severity.from(string: (value?["severity"] as? String) ?? "unknown"),
                         summary: (value?["description"] as? String) ?? type)
        })
        SupplyChainLog.shared.record(
            "[socket.dev] ✓  \(ecosystem)/\(name)@\(version) — \(result.compromised.count) compromise, \(result.vulnerabilities.count) CVE")
        remember(key, result)
        return result
    }

    private func remember(_ key: CacheKey, _ result: CheckResult) {
        cache[key] = result
        if cache.count > Self.cacheCap {
            let toDrop = cache.count - Self.cacheCap
            for k in cache.keys.prefix(toDrop) {
                cache.removeValue(forKey: k)
            }
        }
    }

    // MARK: Package-URL lookup (every ecosystem but npm)

    /// The package URL socket.dev looks a package up by
    /// (`pkg:<type>/<namespace>/<name>@<version>`), from the names the
    /// proxy reads off registry URLs. nil: an ecosystem it doesn't cover.
    static func purl(ecosystem: String, name: String, version: String) -> String? {
        func enc(_ s: String) -> String? {
            var allowed = CharacterSet.alphanumerics
            allowed.insert(charactersIn: ".-_~+")
            return s.addingPercentEncoding(withAllowedCharacters: allowed)
        }
        guard !name.isEmpty, !version.isEmpty, let v = enc(version) else { return nil }
        func path(_ parts: [String]) -> String? {
            let e = parts.compactMap(enc)
            return e.count == parts.count && !parts.contains(where: \.isEmpty) ? e.joined(separator: "/") : nil
        }
        let type: String, segments: [String]
        switch ecosystem {
        case "pypi":
            // PEP 503 normalization, as the PURL spec has it for PyPI.
            type = "pypi"
            segments = [name.lowercased().replacingOccurrences(of: "_", with: "-")
                .replacingOccurrences(of: ".", with: "-")]
        case "cargo":     type = "cargo"; segments = [name]
        case "rubygems":  type = "gem"; segments = [name]
        case "nuget":     type = "nuget"; segments = [name]
        case "maven":
            // "group:artifact" → group/artifact
            let ga = name.split(separator: ":", maxSplits: 1).map(String.init)
            guard ga.count == 2 else { return nil }
            type = "maven"; segments = ga
        case "packagist":
            let vn = name.split(separator: "/", maxSplits: 1).map(String.init)
            guard vn.count == 2 else { return nil }
            type = "composer"; segments = vn
        case "go":
            // proxy.golang.org case-encodes capitals ("!x" → "X").
            var module = ""
            var bang = false
            for ch in name {
                if ch == "!" { bang = true; continue }
                module.append(bang ? Character(ch.uppercased()) : ch)
                bang = false
            }
            type = "golang"; segments = module.split(separator: "/").map(String.init)
            guard !segments.isEmpty else { return nil }
        default:
            return nil
        }
        guard let p = path(segments) else { return nil }
        return "pkg:\(type)/\(p)@\(v)"
    }

    /// Org slugs, by API key: the org-scoped lookup is the current one;
    /// the plain /v0/purl is deprecated (still served).
    private var orgSlugs: [String: String?] = [:]

    private func orgSlug(apiKey: String) async -> String? {
        if let known = orgSlugs[apiKey] { return known }
        guard let url = URL(string: "https://api.socket.dev/v0/organizations") else { return nil }
        var req = URLRequest(url: url)
        Self.authorize(&req, apiKey: apiKey)
        guard let (data, resp) = try? await session.data(for: req),
              (resp as? HTTPURLResponse)?.statusCode == 200,
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let orgs = obj["organizations"] as? [String: Any] else {
            return nil   // not remembered: asked again next time
        }
        let slug = orgs.values.compactMap { ($0 as? [String: Any])?["slug"] as? String }.sorted().first
        orgSlugs[apiKey] = .some(slug)
        return slug
    }

    private static func authorize(_ req: inout URLRequest, apiKey: String) {
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        req.setValue("bromure-ac/2.0", forHTTPHeaderField: "User-Agent")
        // Basic auth: key as username, empty password.
        let basic = "\(apiKey):".data(using: .utf8)!.base64EncodedString()
        req.setValue("Basic \(basic)", forHTTPHeaderField: "Authorization")
    }

    /// One package by its package URL. Waits (poll) up to 20 s for an
    /// analysis socket.dev hasn't finished; one still pending is no
    /// verdict (nil), like a failed lookup.
    private func checkPURL(_ purl: String, label: String, apiKey: String) async -> CheckResult? {
        await acquireSlot()
        defer { releaseSlot() }
        let query = "alerts=true&compact=true&poll=true&timeoutSec=20"
        var endpoints: [String] = []
        if let slug = await orgSlug(apiKey: apiKey),
           let s = slug.addingPercentEncoding(withAllowedCharacters: .alphanumerics.union(.init(charactersIn: "-_."))) {
            endpoints.append("https://api.socket.dev/v0/orgs/\(s)/purl?\(query)")
        }
        endpoints.append("https://api.socket.dev/v0/purl?\(query)")
        let body = (try? JSONSerialization.data(withJSONObject: ["components": [["purl": purl]]])) ?? Data()
        for (i, urlStr) in endpoints.enumerated() {
            guard let url = URL(string: urlStr) else { continue }
            var req = URLRequest(url: url)
            req.httpMethod = "POST"
            Self.authorize(&req, apiKey: apiKey)
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.setValue("application/x-ndjson", forHTTPHeaderField: "Accept")
            req.httpBody = body
            req.timeoutInterval = 45
            SupplyChainLog.shared.record("[socket.dev] →  POST \(urlStr) \(purl)")
            var response: (Data, URLResponse)?
            for attempt in 1...Self.maxRetries {
                do { response = try await session.data(for: req); break }
                catch {
                    let code = (error as? URLError)?.code
                    let retriable = [.timedOut, .networkConnectionLost, .cannotConnectToHost,
                                     .dnsLookupFailed, .resourceUnavailable].contains(code)
                    if !retriable || attempt == Self.maxRetries {
                        SupplyChainLog.shared.record("[socket.dev] ✗  \(label) — network error: \(error.localizedDescription)")
                        break
                    }
                    try? await Task.sleep(nanoseconds: UInt64(attempt) * 250_000_000)
                }
            }
            guard let (data, resp) = response else { return nil }
            let status = (resp as? HTTPURLResponse)?.statusCode ?? 0
            if status != 200 {
                let bodyPreview = String(data: data.prefix(200), encoding: .utf8) ?? ""
                SupplyChainLog.shared.record("[socket.dev] ✗  \(label) — HTTP \(status): \(bodyPreview)")
                // The org-scoped route refused (scope, plan): the plain one.
                if i < endpoints.count - 1, [401, 403, 404].contains(status) { continue }
                return nil
            }
            guard let result = Self.parsePURLResponse(data, purl: purl) else {
                SupplyChainLog.shared.record("[socket.dev] ✗  \(label) — no verdict in the response (pending analysis, or not found)")
                return nil
            }
            SupplyChainLog.shared.record(
                "[socket.dev] ✓  \(label) — \(result.compromised.count) compromise, \(result.vulnerabilities.count) CVE")
            return result
        }
        return nil
    }

    /// Alerts that mean socket.dev has no verdict on the package: an
    /// analysis still under way, or a package it can't resolve (a new
    /// upload, a name it doesn't know). Read as clean, such a package was
    /// let through — and remembered so for the rest of the run.
    static let noVerdictAlerts: Set<String> = ["pendingScan", "notFound"]

    /// The /purl response (NDJSON: artifacts, purlError, summary lines;
    /// a JSON array of the same is read too): the verdict for the one
    /// package asked about, or nil (an error line, no artifact, or a
    /// no-verdict alert).
    static func parsePURLResponse(_ data: Data, purl: String) -> CheckResult? {
        var objects: [[String: Any]] = []
        if let arr = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] {
            objects = arr
        } else {
            for line in String(decoding: data, as: UTF8.self).split(whereSeparator: \.isNewline) {
                if let obj = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any] {
                    objects.append(obj)
                }
            }
        }
        for obj in objects {
            guard obj["_type"] == nil,   // purlError / summary lines
                  obj["name"] != nil || obj["inputPurl"] != nil else { continue }
            let alerts = (obj["alerts"] as? [[String: Any]]) ?? []
            if alerts.contains(where: { noVerdictAlerts.contains(($0["type"] as? String) ?? "") }) { return nil }
            return classify(alerts.map { a in
                let type = (a["type"] as? String) ?? ""
                let props = a["props"] as? [String: Any]
                let summary = (props?["title"] as? String) ?? (props?["description"] as? String)
                    ?? (props?["cveId"] as? String) ?? type
                return Issue(type: type, severity: Severity.from(string: (a["severity"] as? String) ?? "unknown"),
                             summary: summary)
            })
        }
        return nil
    }
}
