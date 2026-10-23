import Foundation
import Testing
@testable import bromure_ac

/// A kubeconfig imported into a RUNNING workspace: the live credential
/// refresh swapped its tokens but never registered its cluster CA or client
/// certificate, so the proxy refused the API server ("signed by a CA the
/// host running Bromure AC does not trust") until the workspace restarted.
/// And one workspace closing stopped every workspace's exec-credential
/// refresh.
@Suite("Kubernetes: a live kubeconfig is trusted and authenticated at once")
@MainActor
struct KubeLiveTrustTests {
    private static func selfSignedPEM() throws -> String? {
        guard FileManager.default.isExecutableFile(atPath: "/usr/bin/openssl") else { return nil }
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("kca-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        p.arguments = ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=kubernetes",
                       "-keyout", dir.appendingPathComponent("k.pem").path, "-out", dir.appendingPathComponent("c.pem").path]
        p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
        try p.run(); p.waitUntilExit()
        return try? String(contentsOf: dir.appendingPathComponent("c.pem"), encoding: .utf8)
    }

    @Test("Applying a workspace's kubeconfigs registers each cluster's CA, and a removed one goes")
    func liveCA() throws {
        let ca = try #require(try Self.selfSignedPEM())
        let pid = UUID(), other = UUID()
        var p = Profile(name: "glm", tool: .claude, authMode: .token)
        p.kubeconfigs = [KubeconfigEntry(name: "kubernetes-admin@kubernetes", serverURL: "https://10.163.15.50:6443",
                                         caCertPEM: ca, auth: .bearerToken("real"))]
        let ids = ClientIdentityRegistry(), cas = ClusterCATrustRegistry(), poller = ExecCredentialPoller()
        let swapper = TokenSwapper(consent: ConsentBroker())
        cas.setCA(pem: ca, host: "k8s.other:443", profileID: other)

        let mat = KubeconfigMaterializer().materialize(profile: p, bromureCAPEM: "PEM")
        MitmEngine.applyKubeMaterial(mat, profileID: pid, identities: ids, clusterCAs: cas, poller: poller, swapper: swapper)
        #expect(cas.ca(for: "10.163.15.50:6443", profileID: pid) != nil)
        #expect(cas.ca(for: "10.163.15.50", profileID: pid) != nil)

        // The entry removed while the VM runs: no longer trusted; another
        // workspace's cluster untouched.
        p.kubeconfigs = []
        MitmEngine.applyKubeMaterial(KubeconfigMaterializer().materialize(profile: p, bromureCAPEM: "PEM"),
                                     profileID: pid, identities: ids, clusterCAs: cas, poller: poller, swapper: swapper)
        #expect(cas.ca(for: "10.163.15.50", profileID: pid) == nil)
        #expect(cas.ca(for: "k8s.other", profileID: other) != nil)
    }

    @Test("Stopping one workspace's exec pollers leaves the others running")
    func pollerPerWorkspace() {
        let a = UUID(), b = UUID()
        let poller = ExecCredentialPoller(), swapper = TokenSwapper(consent: ConsentBroker())
        func ctx() -> KubeconfigMaterializer.ExecContext {
            KubeconfigMaterializer.ExecContext(entryID: UUID(), host: "k8s.example.com", fakeToken: "brm-k8s-x",
                                               command: "/usr/bin/false", args: [], refreshSeconds: 3600)
        }
        let ca = ctx(), cb = ctx()
        poller.start([ca], profileID: a, swapper: swapper)
        poller.start([cb], profileID: b, swapper: swapper)
        poller.stopAll(profileID: a)
        #expect(poller.entries(for: a).isEmpty)
        #expect(poller.entries(for: b) == [cb.entryID])
        poller.stopAll()
    }

    /// Finding (CWE-362): "A live kubeconfig refresh cancels another
    /// workspace's exec poller when entry ids match". Tasks were keyed by
    /// the entry id alone, so refreshing a duplicated workspace (same entry
    /// ids) cancelled the original's poller and took its slot.
    @Test("A workspace's refresh restarts only its own poller, even for an entry id another workspace shares")
    func pollerSharedEntryID() {
        let a = UUID(), b = UUID(), entry = UUID()
        let poller = ExecCredentialPoller(), swapper = TokenSwapper(consent: ConsentBroker())
        let ctx = KubeconfigMaterializer.ExecContext(entryID: entry, host: "k8s.example.com", fakeToken: "brm-k8s-x",
                                                     command: "/usr/bin/false", args: [], refreshSeconds: 3600)
        poller.start([ctx], profileID: a, swapper: swapper)
        poller.start([ctx], profileID: b, swapper: swapper)
        poller.start([ctx], profileID: a, swapper: swapper)      // a's live refresh
        #expect(poller.entries(for: a) == [entry])
        #expect(poller.entries(for: b) == [entry])
        poller.stopAll(profileID: a)
        #expect(poller.entries(for: a).isEmpty)
        #expect(poller.entries(for: b) == [entry])
        poller.stopAll()
    }

    /// Finding (CWE-362): "A cancelled kube exec poll writes an older token
    /// onto the reused fake". A live push restarted every poller; the run it
    /// replaced still wrote its token when its plugin returned -- after the
    /// new run's, on the same reused fake -- and could put back an entry the
    /// map had dropped.
    @Test("Only the current poller run writes its token; an unchanged context keeps its poller")
    func pollerLateRunWritesNothing() async throws {
        let fm = FileManager.default
        let dir = fm.temporaryDirectory.appendingPathComponent("kube-exec-\(UUID().uuidString)")
        try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: dir) }
        func plugin(_ name: String, token: String, delay: String) throws -> String {
            let path = dir.appendingPathComponent(name).path
            try """
                #!/bin/sh
                echo run >> "\(dir.path)/\(name).runs"
                sleep \(delay)
                echo '{"status":{"token":"\(token)"}}'
                """.write(toFile: path, atomically: true, encoding: .utf8)
            chmod(path, 0o755)
            return path
        }
        let slow = try plugin("slow", token: "token-old", delay: "1")
        let fast = try plugin("fast", token: "token-new", delay: "0")
        let pid = UUID(), entry = UUID(), fake = "brm-k8s-reused"
        let poller = ExecCredentialPoller(), swapper = TokenSwapper(consent: ConsentBroker())
        func real() -> String? { swapper.entries(for: pid).first { $0.fake == fake }?.real }
        func ctx(_ command: String) -> KubeconfigMaterializer.ExecContext {
            .init(entryID: entry, host: "k8s.example.com", fakeToken: fake, command: command, args: [], refreshSeconds: 3600)
        }
        swapper.setMap(TokenMap(entries: [TokenMap.Entry(fake: fake, real: "", host: "k8s.example.com",
                                                         consentCredentialID: "kube:x")]), for: pid)
        // The old run is in its plugin when a live push replaces it.
        poller.sync([ctx(slow)], profileID: pid, swapper: swapper)
        try await Task.sleep(nanoseconds: 200_000_000)
        poller.sync([ctx(fast)], profileID: pid, swapper: swapper)
        for _ in 0..<100 where real() != "token-new" { try await Task.sleep(nanoseconds: 20_000_000) }
        #expect(real() == "token-new")
        try await Task.sleep(nanoseconds: 1_500_000_000)          // the old plugin has returned by now
        #expect(real() == "token-new")
        #expect(swapper.entries(for: pid).first { $0.fake == fake }?.consentCredentialID == "kube:x")

        // An unchanged context keeps its poller: no second run of its plugin.
        poller.sync([ctx(fast)], profileID: pid, swapper: swapper)
        try await Task.sleep(nanoseconds: 300_000_000)
        #expect((try? String(contentsOfFile: dir.appendingPathComponent("fast.runs").path, encoding: .utf8))?
            .split(separator: "\n").count == 1)

        // A removed kubeconfig: a run still in its plugin doesn't put it back.
        poller.sync([ctx(slow)], profileID: pid, swapper: swapper)
        try await Task.sleep(nanoseconds: 200_000_000)
        swapper.setMap(TokenMap(entries: []), for: pid)
        poller.sync([], profileID: pid, swapper: swapper)
        try await Task.sleep(nanoseconds: 1_500_000_000)
        #expect(swapper.entries(for: pid).isEmpty)
        #expect(poller.entries(for: pid).isEmpty)
        poller.stopAll()
    }

    @Test("A duplicated workspace gets its own kubeconfig entry ids")
    func duplicateMintsEntryIDs() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("kube-dup-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let store = ProfileStore(rootDir: root)
        var p = Profile(name: "ws", tool: .claude, authMode: .token)
        p.kubeconfigs = [KubeconfigEntry(name: "prod", serverURL: "https://k8s.example.com:6443", caCertPEM: "",
                                         auth: .bearerToken("real"))]
        try store.save(p)
        let copy = try store.duplicate(p, named: "ws copy")
        #expect(copy.kubeconfigs.count == 1)
        #expect(copy.kubeconfigs[0].id != p.kubeconfigs[0].id)
        #expect(copy.kubeconfigs[0].name == "prod" && copy.kubeconfigs[0].auth == p.kubeconfigs[0].auth)
    }

    @Test("The live credential refresh applies the kubeconfigs' trust, as the launch does")
    func liveRefreshApplies() throws {
        let src = try String(contentsOf: URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/AgentCoding/BromureAC.swift"), encoding: .utf8)
        let live = try #require(src.range(of: "func pushLiveCredentials("))
        let body = src[live.upperBound...].prefix(6000)
        #expect(body.contains("engine.applyKubeMaterial(kubeMat, profileID: profile.id)"))
        #expect(src.components(separatedBy: "engine.applyKubeMaterial(kubeMat").count == 3)   // launch + live
        let engine = try String(contentsOf: URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/AgentCoding/Mitm/MitmEngine.swift"), encoding: .utf8)
        #expect(!engine.contains("execPoller.stopAll()"))
    }
}

/// Finding (CWE-670): "Live refresh publishes an empty Kubernetes exec token
/// before the plugin runs". A live credential push re-minted every exec
/// entry's fake with an empty real token and rewrote the guest kubeconfig
/// with it: kubectl sent an empty bearer until the plugin next ran (never,
/// for refreshSeconds, if it failed). A 1Password-sourced token got its
/// `op://` reference back the same way.
@Suite("Live refresh: a token a refresher already resolved stays in force")
struct LiveRefreshPlaceholderTests {
    func exec(_ args: [String] = ["get-token"]) -> KubeconfigEntry {
        KubeconfigEntry(name: "eks", serverURL: "https://k8s.example.com:6443", caCertPEM: "",
                        auth: .execPlugin(command: "/usr/local/bin/aws", args: args, refreshSeconds: 600))
    }

    @Test("an unchanged exec entry keeps its fake across a re-materialize; a changed plugin gets a new one")
    @MainActor func execFakeStable() throws {
        var p = Profile(name: "ws", tool: .claude, authMode: .token)
        p.kubeconfigs = [exec()]
        let m = KubeconfigMaterializer()
        let first = m.materialize(profile: p, bromureCAPEM: "PEM")
        let fake = try #require(first.execContexts.first?.fakeToken)
        let again = m.materialize(profile: p, bromureCAPEM: "PEM", reusingExec: first.execContexts)
        #expect(again.execContexts.first?.fakeToken == fake)
        #expect(again.yaml.contains(fake))
        // Another plugin invocation is another credential: a fresh fake.
        p.kubeconfigs[0].auth = .execPlugin(command: "/usr/local/bin/aws", args: ["other"], refreshSeconds: 600)
        let changed = m.materialize(profile: p, bromureCAPEM: "PEM", reusingExec: first.execContexts)
        #expect(changed.execContexts.first?.fakeToken != fake)
    }

    @Test("the merge carries a resolved token onto a placeholder for the same fake and host, with the fresh consent")
    func mergeCarriesResolved() {
        let current = [
            TokenMap.Entry(fake: "brm-k8s-a", real: "resolved-exec", host: "k8s.example.com"),
            TokenMap.Entry(fake: "brm-op-b", real: "resolved-op", host: "api.example.com"),
            TokenMap.Entry(fake: "brm-old", real: "old-real", host: "api.example.com"),
        ]
        let fresh = [
            TokenMap.Entry(fake: "brm-k8s-a", real: "", host: "k8s.example.com",
                           consentCredentialID: "kube:x", consentDisplayName: "kubeconfig"),
            TokenMap.Entry(fake: "brm-op-b", real: "op://vault/item/field", host: "api.example.com"),
            TokenMap.Entry(fake: "brm-k8s-new", real: "", host: "k8s.example.com"),        // nothing resolved yet
            TokenMap.Entry(fake: "brm-k8s-a", real: "", host: "other.example.com"),        // another host: not carried
            TokenMap.Entry(fake: "brm-static", real: "edited", host: "api.example.com"),
        ]
        let merged = TokenMap.liveMerge(fresh: fresh, current: current).entries
        func real(_ fake: String, _ host: String) -> String? { merged.first { $0.fake == fake && $0.host == host }?.real }
        #expect(real("brm-k8s-a", "k8s.example.com") == "resolved-exec")
        #expect(merged.first { $0.fake == "brm-k8s-a" && $0.host == "k8s.example.com" }?.consentCredentialID == "kube:x")
        #expect(real("brm-op-b", "api.example.com") == "resolved-op")
        #expect(real("brm-k8s-new", "k8s.example.com") == "")
        #expect(real("brm-k8s-a", "other.example.com") == "")
        #expect(real("brm-static", "api.example.com") == "edited")
        #expect(real("brm-old", "api.example.com") == "old-real")             // a not-reissued fake stays
        #expect(merged.count == 6)
    }

    @Test("the live push re-materializes with the poller's contexts and merges, not replaces")
    func livePushWiring() throws {
        let src = try String(contentsOf: URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/AgentCoding/BromureAC.swift"), encoding: .utf8)
        let live = try #require(src.range(of: "func pushLiveCredentials("))
        let body = src[live.upperBound...].prefix(6000)
        #expect(body.contains("reusingExec: engine.kubeExecContexts(for: profile.id)"))
        #expect(body.contains("TokenMap.liveMerge(fresh: fresh.entries"))
    }
}
