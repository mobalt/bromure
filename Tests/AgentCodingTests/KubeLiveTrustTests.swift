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
