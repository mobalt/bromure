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
            TokenMap.Entry(fake: "brm-op-b", real: "resolved-op", host: "api.example.com",
                           resolvedFrom: "op://vault/item/field"),
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

    /// Finding (CWE-670): "Live merge keeps the previous secret when a
    /// credential becomes an op:// reference". With OpenShell credential
    /// placeholders the fake is `openshell:resolve:env:VAR` whatever the
    /// secret: a literal token saved as a new `op://` value kept the old
    /// secret for the rest of the session, and the 1Password loop -- started
    /// at launch for a fake it re-derived itself -- never resolved it.
    @Test("a 1Password value takes only the secret resolved from that same reference; the loop follows the map's fakes")
    @MainActor func opReferenceCarriesOnlyItsOwnSecret() {
        let fake = "openshell:resolve:env:GITHUB_TOKEN"
        let fresh = [TokenMap.Entry(fake: fake, real: "op://vault/item/token", host: "github.com",
                                    paths: ["/repos/**"])]
        func merged(_ held: TokenMap.Entry) -> TokenMap.Entry? {
            TokenMap.liveMerge(fresh: fresh, current: [held]).entries.first { $0.fake == fake && $0.host == "github.com" }
        }
        // The old literal secret: not this reference's, so not carried.
        #expect(merged(TokenMap.Entry(fake: fake, real: "ghp_old", host: "github.com"))?.real == "op://vault/item/token")
        // Resolved from another reference: not carried either.
        #expect(merged(TokenMap.Entry(fake: fake, real: "ghp_other", host: "github.com",
                                      resolvedFrom: "op://vault/other/token"))?.real == "op://vault/item/token")
        // Resolved from this very reference: kept (no blank between pushes).
        let same = merged(TokenMap.Entry(fake: fake, real: "ghp_new", host: "github.com",
                                         resolvedFrom: "op://vault/item/token"))
        #expect(same?.real == "ghp_new" && same?.resolvedFrom == "op://vault/item/token" && same?.paths == ["/repos/**"])

        // The loop resolves every op:// value at the fake the map holds, a
        // placeholder included, one Ref per fake and reference with its hosts.
        let entries = fresh + [
            TokenMap.Entry(fake: fake, real: "op://vault/item/token", host: "api.github.com"),
            TokenMap.Entry(fake: "brm_x", real: "literal", host: "example.com"),
        ]
        let refs = OnePasswordRefresher.refs(in: entries)
        #expect(refs.count == 1 && refs.first?.fake == fake && refs.first?.opRef == "op://vault/item/token")
        #expect(refs.first?.hosts == ["github.com", "api.github.com"])

        // Starting it blanks a still-unresolved value (keeping the entry's
        // path binding), and leaves one already resolved from the reference.
        let swapper = TokenSwapper(consent: ConsentBroker())
        let pid = UUID()
        swapper.setMap(TokenMap(entries: [
            TokenMap.Entry(fake: fake, real: "op://vault/item/token", host: "github.com", paths: ["/repos/**"]),
            TokenMap.Entry(fake: fake, real: "ghp_new", host: "api.github.com", resolvedFrom: "op://vault/item/token"),
        ]), for: pid)
        let loop = OnePasswordRefresher()
        loop.start(profileID: pid, refs: refs, swapper: swapper)
        loop.stop(profileID: pid)   // before its task runs: no `op` call from a test
        let after = swapper.entries(for: pid)
        let blanked = after.first { $0.host == "github.com" }
        #expect(blanked?.real == "" && blanked?.paths == ["/repos/**"])
        #expect(after.first { $0.host == "api.github.com" }?.real == "ghp_new")
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
        #expect(body.contains("refs: OnePasswordRefresher.refs(in: fresh.entries)"))
    }
}
