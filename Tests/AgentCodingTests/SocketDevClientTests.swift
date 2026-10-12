import Foundation
import Testing
@testable import bromure_ac

/// Issue #43: with a socket.dev key, every Python package asked "Bromure
/// couldn't reach socket.dev to vet pypi six@1.17.0…" — the per-package
/// `/v0/<eco>/<name>/<version>/issues` route exists for npm only (PyPI
/// got 404 "API route not found"), so every lookup failed. Every other
/// ecosystem now goes through the package-URL lookup.
@Suite("socket.dev client")
struct SocketDevClientTests {
    @Test("package URLs for each ecosystem the proxy reads")
    func purls() {
        #expect(SocketDevClient.purl(ecosystem: "pypi", name: "six", version: "1.17.0") == "pkg:pypi/six@1.17.0")
        // PEP 503 names, as wheels spell them.
        #expect(SocketDevClient.purl(ecosystem: "pypi", name: "Typing_Extensions", version: "4.12.2")
                == "pkg:pypi/typing-extensions@4.12.2")
        #expect(SocketDevClient.purl(ecosystem: "cargo", name: "serde", version: "1.0.210") == "pkg:cargo/serde@1.0.210")
        #expect(SocketDevClient.purl(ecosystem: "rubygems", name: "rails", version: "7.1.3") == "pkg:gem/rails@7.1.3")
        #expect(SocketDevClient.purl(ecosystem: "nuget", name: "newtonsoft.json", version: "13.0.3")
                == "pkg:nuget/newtonsoft.json@13.0.3")
        #expect(SocketDevClient.purl(ecosystem: "maven", name: "org.apache.commons:commons-lang3", version: "3.14.0")
                == "pkg:maven/org.apache.commons/commons-lang3@3.14.0")
        #expect(SocketDevClient.purl(ecosystem: "packagist", name: "monolog/monolog", version: "3.7.0")
                == "pkg:composer/monolog/monolog@3.7.0")
        // proxy.golang.org case-encodes capitals.
        #expect(SocketDevClient.purl(ecosystem: "go", name: "github.com/!burnt!sushi/toml", version: "v1.4.0")
                == "pkg:golang/github.com/BurntSushi/toml@v1.4.0")
        // Nothing for what it can't name.
        #expect(SocketDevClient.purl(ecosystem: "maven", name: "no-group", version: "1") == nil)
        #expect(SocketDevClient.purl(ecosystem: "npm-ish", name: "x", version: "1") == nil)
        #expect(SocketDevClient.purl(ecosystem: "pypi", name: "x", version: "") == nil)
    }

    @Test("a package-URL reply: malware blocks, CVEs are counted, pending is no verdict")
    func parse() {
        let purl = "pkg:pypi/six@1.17.0"
        func ndjson(_ lines: [[String: Any]]) -> Data {
            Data(lines.map { String(decoding: try! JSONSerialization.data(withJSONObject: $0), as: UTF8.self) }
                .joined(separator: "\n").utf8)
        }
        let clean = SocketDevClient.parsePURLResponse(ndjson([
            ["type": "pypi", "name": "six", "version": "1.17.0", "inputPurl": purl,
             "alerts": [["type": "networkAccess", "severity": "middle"]]],
            ["_type": "summary", "purl_input": 1],
        ]), purl: purl)
        #expect(clean != nil && clean!.compromised.isEmpty && clean!.vulnerabilities.isEmpty)

        let bad = SocketDevClient.parsePURLResponse(ndjson([
            ["type": "pypi", "name": "six", "version": "1.17.0", "inputPurl": purl,
             "alerts": [["type": "malware", "severity": "critical", "props": ["description": "steals tokens"]],
                        ["type": "criticalCVE", "severity": "critical", "props": ["cveId": "CVE-2026-1"]]]],
        ]), purl: purl)
        #expect(bad?.compromised.first?.type == "malware")
        #expect(bad?.compromised.first?.summary == "steals tokens")
        #expect(bad?.vulnerabilities.first?.summary == "CVE-2026-1")

        // Still being analyzed, or not resolved: no verdict.
        #expect(SocketDevClient.parsePURLResponse(ndjson([
            ["type": "pypi", "name": "six", "version": "1.17.0", "inputPurl": purl,
             "alerts": [["key": "socket-pending-scan", "type": "pendingScan", "severity": "low"]]],
        ]), purl: purl) == nil)
        #expect(SocketDevClient.parsePURLResponse(ndjson([
            ["_type": "purlError", "value": ["inputPurl": purl, "error": "not found", "retryable": false]],
        ]), purl: purl) == nil)
    }
}
