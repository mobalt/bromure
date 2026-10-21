import Foundation
import Testing
import SandboxEngine
@testable import bromure_ac

@Suite("OpenShell policy advisor")
struct OpenShellAdvisorTests {
    static let base = """
    version: 1
    # my policy
    network_policies:
        github:            # four-space indent on purpose
            endpoints:
                - { host: api.github.com, port: 443, protocol: rest, enforcement: enforce, access: read-only }

    filesystem_policy:
      read_only: [/usr]
    """

    /// A fresh advisor wired to an in-memory "workspace".
    private func advisor(mode: OpenShellAdvisorMode, policy: String = base,
                         scopes: [String] = ["github.com"]) -> (OpenShellAdvisor, UUID, Box) {
        let a = OpenShellAdvisor()
        let pid = UUID()
        let box = Box(policy: policy)
        a.modeProvider = { _ in mode }
        a.policyProvider = { _ in try? OpenShellPolicy.parse(box.policy) }
        a.credentialScopesProvider = { _ in scopes }
        a.applyApproved = { _, p in
            do { box.policy = try OpenShellPolicy.insertingRules(p.yaml, into: box.policy); return nil }
            catch { return "\(error)" }
        }
        return (a, pid, box)
    }

    final class Box: @unchecked Sendable { var policy: String; init(policy: String) { self.policy = policy } }

    private func proposal(_ rule: String, host: String, method: String = "GET", path: String = "/**",
                          proto: String = "rest") -> Data {
        let json: [String: Any] = [
            "intent_summary": "test",
            "operations": [["addRule": ["ruleName": rule, "rule": [
                "endpoints": [["host": host, "port": 443, "protocol": proto, "enforcement": "enforce",
                               "rules": [["allow": ["method": method, "path": path]]]]],
                "binaries": [["path": "/usr/bin/curl"]]]]]],
        ]
        return try! JSONSerialization.data(withJSONObject: json)
    }

    @Test("Rules are inserted into the policy text in place, keeping comments and indentation")
    func insertion() throws {
        let rule = try #require(try OpenShellPolicy.parse("""
        version: 1
        network_policies:
          docs:
            endpoints: [{ host: docs.example.com, port: 443 }]
        """).networkPolicies.first)
        let out = try OpenShellPolicy.insertingRules(OpenShellPolicy.yaml(rule: rule), into: Self.base)
        #expect(out.contains("# my policy"))
        #expect(out.contains("    \"docs\":"))                           // matched the 4-space indent
        let p = try OpenShellPolicy.parse(out)
        #expect(p.networkPolicies.map(\.key) == ["github", "docs"])
        // A policy with no network_policies gets the section appended.
        let bare = try OpenShellPolicy.insertingRules(OpenShellPolicy.yaml(rule: rule), into: "version: 1\n")
        #expect(try OpenShellPolicy.parse(bare).networkPolicies.map(\.key) == ["docs"])
    }

    @Test("Emitted YAML round-trips every endpoint feature")
    func roundTrip() throws {
        let src = """
        version: 1
        network_policies:
          r:
            name: Rich
            endpoints:
              - host: api.example.com
                ports: [443, 8443]
                path: /v1/**
                allowed_ips: [10.0.0.0/8]
                protocol: rest
                enforcement: enforce
                allow_encoded_slash: true
                rules:
                  - allow: { method: GET, path: "/v1/**", query: { tag: { any: ["a*"] } } }
                deny_rules:
                  - { method: DELETE, path: "/v1/**" }
              - { host: mcp.example.com, port: 443, protocol: mcp, enforcement: enforce,
                  mcp: { versions: ["2025-06-18"] }, rules: [{ allow: { method: tools/call, tool: search } }] }
              - { host: gql.example.com, port: 443, protocol: graphql, enforcement: enforce,
                  rules: [{ allow: { operation_type: query, fields: [viewer] } }] }
            binaries: [{ path: /usr/bin/curl }]
        """
        let rule = try #require(try OpenShellPolicy.parse(src).networkPolicies.first)
        let again = try OpenShellPolicy.parse("version: 1\nnetwork_policies:\n" + OpenShellPolicy.yaml(rule: rule) + "\n")
        #expect(again.networkPolicies.first == rule)
    }

    @Test("Agent JSON: allowed fields only; tcp / tls skip refused")
    func agentJSON() {
        let ok = OpenShellAdvisor.rule(fromAgentJSON: [
            "endpoints": [["host": "api.example.com", "port": 443, "protocol": "rest", "enforcement": "enforce",
                           "rules": [["allow": ["method": "PUT", "path": "/x/**"]]]]],
            "binaries": [["path": "/usr/bin/gh"]]], key: "x_write")
        guard case .ok(let rule) = ok else { Issue.record("expected ok"); return }
        #expect(rule.endpoints.first?.rules.first?.method == "PUT")
        #expect(rule.binaries == ["/usr/bin/gh"])
        if case .ok = OpenShellAdvisor.rule(fromAgentJSON: ["endpoints": [["host": "db.example.com", "port": 5432, "protocol": "tcp"]]], key: "db") {
            Issue.record("tcp must be refused")
        }
        if case .ok = OpenShellAdvisor.rule(fromAgentJSON: ["endpoints": [["host": "a.example.com", "port": 443, "tls": "skip"]]], key: "a") {
            Issue.record("tls: skip must be refused")
        }
        if case .ok = OpenShellAdvisor.rule(fromAgentJSON: ["endpoints": [["host": "a.example.com", "port": 443]]], key: "_provider_x") {
            Issue.record("reserved key must be refused")
        }
    }

    @Test("Risk-free proposals auto-approve and load; credentialed ones wait")
    func autoApproval() async throws {
        let (a, pid, box) = advisor(mode: .auto)
        let r1 = a.submit(profileID: pid, body: proposal("cdn_read", host: "cdn.example.org"))
        let id1 = try #require((r1["accepted_chunk_ids"] as? [String])?.first)
        try await Task.sleep(nanoseconds: 200_000_000)
        #expect(a.proposal(id: id1, profileID: pid)?.status == .approved)
        #expect(box.policy.contains("cdn.example.org"))

        // A write on the credentialed github host: capability_expansion → review.
        let r2 = a.submit(profileID: pid, body: proposal("gh_write", host: "api.github.com", method: "PUT", path: "/repos/a/b/**"))
        let id2 = try #require((r2["accepted_chunk_ids"] as? [String])?.first)
        let p2 = try #require(a.proposal(id: id2, profileID: pid))
        #expect(p2.findings.contains("capability_expansion"))
        #expect(p2.status == .pending)
        // New reach to a credentialed host.
        let r3 = a.submit(profileID: pid, body: proposal("gh_web", host: "github.com"))
        let p3 = try #require(a.proposal(id: (r3["accepted_chunk_ids"] as? [String])!.first!, profileID: pid))
        #expect(p3.findings.contains("credential_reach_expansion"))
    }

    @Test("Blocked connections become drafts; an agent proposal supersedes the draft")
    func drafts() throws {
        let (a, pid, _) = advisor(mode: .review)
        a.recordDenial(profileID: pid, layer: "sni", host: "pypi.org", port: 443, method: nil, path: nil, reason: "no rule")
        a.recordDenial(profileID: pid, layer: "sni", host: "pypi.org", port: 443, method: nil, path: nil, reason: "no rule")
        a.recordDenial(profileID: pid, layer: "l4", host: "10.1.2.3", port: 5432, method: nil, path: nil, reason: "no rule")
        let drafts = a.pending(for: pid)
        #expect(drafts.count == 1)
        #expect(drafts.first?.source == "mechanistic")
        _ = a.submit(profileID: pid, body: proposal("pypi_read", host: "pypi.org"))
        let all = a.proposals(for: pid)
        #expect(all.first { $0.source == "mechanistic" }?.status == .rejected)
        #expect(a.pending(for: pid).map(\.rule.key) == ["pypi_read"])
    }

    @Test("Allow from the drawer: the rule goes in at once and names the program the attestor reported")
    func allowNamesProgram() async throws {
        let (a, pid, box) = advisor(mode: .review)
        // A draft for the same destination is settled by the allow.
        a.recordDenial(profileID: pid, layer: "l4", host: "www.bromure.io", port: 443, method: nil, path: nil, reason: "no rule")
        BinaryIdentityService.shared.noteExe("/usr/bin/curl", profileID: pid, destinations: ["www.bromure.io"], port: 443)
        let error = await a.allow(profileID: pid, host: "www.bromure.io", port: 443)
        #expect(error == nil)
        let policy = try OpenShellPolicy.parse(box.policy)
        let rule = try #require(policy.networkPolicies.first { $0.key == "allow_www_bromure_io_443_curl" })
        #expect(rule.binaries == ["/usr/bin/curl"])
        #expect(rule.endpoints.first?.host == "www.bromure.io")
        #expect(a.pending(for: pid).isEmpty)
    }

    @Test("Allow with no attested program: a host-and-port rule for any program")
    func allowWithoutProgram() async throws {
        let (a, pid, box) = advisor(mode: .review)
        #expect(await a.allow(profileID: pid, host: "pypi.org", port: 443) == nil)
        let rule = try #require(try OpenShellPolicy.parse(box.policy).networkPolicies.first { $0.key == "allow_pypi_org_443" })
        #expect(rule.binaries.isEmpty)
        // Allowing it again is refused, not duplicated.
        #expect(await a.allow(profileID: pid, host: "pypi.org", port: 443) != nil)
    }

    /// Finding (CWE-670): "Sandbox drawer Allow saves a no-op rule when
    /// Enforce binaries is on". The MiTM recorded the program under the
    /// destination IP only and the row's host is the SNI, so Allow found no
    /// program and saved a rule listing none — which allows nothing there.
    @Test("Under Enforce binaries: Allow finds the program by host or IP, and refuses when there's none")
    func allowUnderEnforce() async throws {
        let (a, pid, box) = advisor(mode: .review)
        a.enforceBinariesProvider = { _ in true }
        // The MiTM's path: identity asked by IP, then the SNI learned.
        BinaryIdentityService.shared.noteExe("/usr/bin/pip", profileID: pid, destinations: ["151.101.0.223"], port: 443)
        let identity = OpenShellPolicy.BinaryIdentity(exe: "/usr/bin/pip", sha256: "", ancestors: [])
        BinaryIdentityService.shared.noteHost(identity, profileID: pid, host: "pypi.org", port: 443)
        #expect(await a.allow(profileID: pid, host: "pypi.org", port: 443) == nil)
        let rule = try #require(try OpenShellPolicy.parse(box.policy).networkPolicies.first { $0.key.hasPrefix("allow_pypi_org_443") })
        #expect(rule.binaries == ["/usr/bin/pip"])
        // Known by IP only (as the row's dst_ip shows it): found too.
        BinaryIdentityService.shared.noteExe("/usr/bin/curl", profileID: pid, destinations: ["140.82.112.3"], port: 8443)
        #expect(await a.allow(profileID: pid, host: "github.com", port: 8443, ip: "140.82.112.3") == nil)
        #expect(try OpenShellPolicy.parse(box.policy).networkPolicies.contains { $0.key == "allow_github_com_8443_curl" })
        // No program known at all: refused, nothing saved, no draft queued.
        let before = box.policy
        let refused = await a.allow(profileID: pid, host: "files.example.com", port: 443)
        #expect(refused?.contains("Enforce binaries") == true)
        #expect(box.policy == before)
        a.recordDenial(profileID: pid, layer: "sni", host: "files.example.com", port: 443, method: nil, path: nil, reason: "no rule")
        #expect(a.pending(for: pid).isEmpty)
    }

    @Test("A MiTM firewall row carries its destination IP (dst_ip)")
    func timelineReadsDstIP() {
        let e = SecurityTimeline.map(profileID: UUID(), eventType: "egress.firewall",
                                           eventData: ["action": .string("deny"), "host": .string("pypi.org"),
                                                       "port": .int(443), "layer": .string("sni"),
                                                       "dst_ip": .string("151.101.0.223")], now: Date())
        #expect(e?.firewall?.ip == "151.101.0.223")
    }

    @Test("policy.local routes: feature_disabled when off; denials, policy, proposal wait")
    func agentAPI() async throws {
        let (off, offPID, _) = advisor(mode: .off)
        let (s0, _, _) = await off.handle(profileID: offPID, method: "GET", target: "/v1/policy/current", body: Data(),
                                         policyReloaded: { _ in false })
        #expect(s0 == 404)

        let (a, pid, box) = advisor(mode: .review)
        a.recordDenial(profileID: pid, layer: "l7", host: "api.github.com", port: 443, method: "POST",
                       path: "/repos/a/b/issues?token=secret", reason: "not permitted")
        let (s1, _, d1) = await a.handle(profileID: pid, method: "GET", target: "/v1/denials?last=5", body: Data(),
                                         policyReloaded: { _ in false })
        #expect(s1 == 200)
        let text = String(decoding: d1, as: UTF8.self)
        #expect(text.contains("HTTP:POST api.github.com:443"))
        #expect(!text.contains("secret"))

        let (s2, type, d2) = await a.handle(profileID: pid, method: "GET", target: "/v1/policy/current", body: Data(),
                                            policyReloaded: { _ in false })
        #expect(s2 == 200 && type == "application/yaml")
        #expect(String(decoding: d2, as: UTF8.self).contains("api.github.com"))

        let (s3, _, d3) = await a.handle(profileID: pid, method: "POST", target: "/v1/proposals",
                                         body: proposal("docs", host: "docs.example.org"), policyReloaded: { _ in false })
        #expect(s3 == 202)
        let id = try #require(((try JSONSerialization.jsonObject(with: d3)) as? [String: Any])?["accepted_chunk_ids"] as? [String]).first!
        // Approve in the background; /wait returns once the rule is loaded.
        Task {
            try? await Task.sleep(nanoseconds: 300_000_000)
            await a.approve(id: id, profileID: pid)
        }
        let (s4, _, d4) = await a.handle(profileID: pid, method: "GET", target: "/v1/proposals/\(id)/wait?timeout=5",
                                         body: Data(), policyReloaded: { key in box.policy.contains(key) })
        #expect(s4 == 200)
        let obj = try #require(try JSONSerialization.jsonObject(with: d4) as? [String: Any])
        #expect(obj["status"] as? String == "approved")
        #expect(obj["policy_reloaded"] as? Bool == true)
    }

    @Test("Control-socket route: list, reject with a reason, approve; decided proposals are final")
    func controlRoute() throws {
        let (a, pid, box) = advisor(mode: .review)
        let r1 = a.submit(profileID: pid, body: proposal("docs_a", host: "a.example.org"))
        let r2 = a.submit(profileID: pid, body: proposal("docs_b", host: "b.example.org"))
        let id1 = try #require((r1["accepted_chunk_ids"] as? [String])?.first)
        let id2 = try #require((r2["accepted_chunk_ids"] as? [String])?.first)
        let route = { (m: String, sub: [String], body: [String: Any]) in
            ACAppDelegate.advisorProposalsRoute(profileID: pid, method: m, sub: sub, body: body, advisor: a)
        }
        let (s0, list) = route("GET", ["proposals"], [:])
        #expect(s0 == 200 && (list["proposals"] as? [[String: Any]])?.count == 2)

        let (s1, rej) = route("POST", ["proposals", id1, "reject"], ["reason": "too broad"])
        #expect(s1 == 200)
        #expect((rej["proposal"] as? [String: Any])?["rejection_reason"] as? String == "too broad")
        #expect(a.proposal(id: id1, profileID: pid)?.status == .rejected)

        let (s2, _) = route("POST", ["proposals", id2, "approve"], [:])
        #expect(s2 == 200)
        #expect(a.proposal(id: id2, profileID: pid)?.status == .approved)
        #expect(box.policy.contains("b.example.org"))

        #expect(route("POST", ["proposals", id1, "approve"], [:]).status == 409)   // already rejected
        #expect(route("POST", ["proposals", "nope", "reject"], [:]).status == 404)
    }
}
