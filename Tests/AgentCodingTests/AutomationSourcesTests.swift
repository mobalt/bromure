import Foundation
import Testing
@testable import bromure_ac

/// Board report: on a fat client the automation editor spun on "loading
/// repositories…" forever — it knew the workspace had a GitHub token but
/// never holds it (credentials aren't mirrored), so it never fetched.
/// It now asks the host (`POST /automation-sources`).
@Suite("Automation editor lists from the host")
struct AutomationSourcesTests {
    @Test("the host's replies read as the editor's lists")
    func decode() async throws {
        let pid = UUID()
        var asked: [[String: Any]] = []
        let replies: [String: [String: Any]] = [
            "repos": ["items": ["acme/web", "acme/api"]],
            "branches": ["items": ["main", "dev"]],
            "dirs": ["items": [], "truncated": true],
            "teams": ["items": [["key": "ENG", "name": "Engineering"]]],
            "projects": ["items": [["id": "p1", "name": "Launch"]]],
        ]
        let s = AutomationSources { body in
            asked.append(body)
            return replies[body["kind"] as? String ?? ""] ?? [:]
        }
        #expect(try await s.repos(pid) == ["acme/web", "acme/api"])
        #expect(try await s.branches(pid, repo: "acme/web") == ["main", "dev"])
        // A tree too big to list: nil, so the folder field is free text.
        #expect(try await s.directories(pid, repo: "acme/web", branch: "main") == nil)
        #expect(try await s.teams(pid) == [LinearPoller.LinearTeam(key: "ENG", name: "Engineering")])
        #expect(try await s.projects(pid) == [LinearPoller.LinearProject(id: "p1", name: "Launch")])
        #expect(asked.allSatisfy { $0["profile"] as? String == pid.uuidString })
        #expect(asked[1]["repo"] as? String == "acme/web")
        #expect(asked[2]["branch"] as? String == "main")
    }

    @Test("a refusal reaches the editor as an error, not an endless spinner")
    func refusal() async {
        let s = AutomationSources { _ in
            throw NSError(domain: "GitHubPoller", code: 401, userInfo: [NSLocalizedDescriptionKey: "Bad credentials"])
        }
        do {
            _ = try await s.repos(UUID())
            Issue.record("expected a throw")
        } catch {
            let ns = error as NSError
            #expect(ns.domain == "GitHubPoller" && ns.code == 401)
        }
    }

    /// Board report: on a fat client the automation editor offered only
    /// the workspace's primary agent — the host's state carried no other.
    @Test("a fat client's workspace has every agent the host lists (tool and sign-in, no keys)")
    func additionalAgents() {
        let w: [String: Any] = ["additionalTools": [
            ["tool": "grok", "authMode": "subscription"],
            ["tool": "codex", "authMode": "token"],
            ["tool": "claude", "authMode": "token"],      // the primary again: dropped
            ["tool": "nope"],                             // unknown: dropped
        ]]
        let specs = RemoteHostController.additionalTools(from: w, primary: .claude)
        #expect(specs.map(\.tool) == [.grok, .codex])
        #expect(specs.first?.authMode == .subscription && specs.allSatisfy { $0.apiKey == nil })
        var p = Profile(name: "codereview", tool: .claude, authMode: .token)
        p.additionalTools = specs
        #expect(p.allToolSpecs.map(\.tool) == [.claude, .grok, .codex])
        // An older host: the primary only, as before.
        #expect(RemoteHostController.additionalTools(from: [:], primary: .claude).isEmpty)
    }
}
