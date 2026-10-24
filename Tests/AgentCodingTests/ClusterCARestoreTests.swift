import Foundation
import Security
import Testing
@testable import bromure_ac

/// Finding (CWE-295): "A failed cluster-CA parse republishes a removed
/// context's CA on the bare host". The bare-host slot (the one the proxy's
/// CONNECT lookup reads) belongs to whichever `host:port` registered last.
/// A rebuild where one context's PEM failed to parse copied that slot
/// forward, so with the last writer removed the surviving context's
/// handshakes were pinned to the removed context's CA.
@Suite("Cluster CA: a failed parse keeps the host's own CA, not its neighbour's")
struct ClusterCARestoreTests {
    private static func selfSignedPEM(_ cn: String) throws -> String? {
        guard FileManager.default.isExecutableFile(atPath: "/usr/bin/openssl") else { return nil }
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("kca-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        p.arguments = ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=\(cn)",
                       "-keyout", dir.appendingPathComponent("k.pem").path, "-out", dir.appendingPathComponent("c.pem").path]
        p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
        try p.run(); p.waitUntilExit()
        return try? String(contentsOf: dir.appendingPathComponent("c.pem"), encoding: .utf8)
    }

    private static func der(_ c: SecCertificate?) -> Data? { c.map { SecCertificateCopyData($0) as Data } }
    private static let broken = "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----"

    @Test("the removed context's CA isn't restored on the bare host; the survivor's own is")
    func ownCARestored() throws {
        let caA = try #require(try Self.selfSignedPEM("cluster-a"))
        let caB = try #require(try Self.selfSignedPEM("cluster-b"))
        let reg = ClusterCATrustRegistry(), pid = UUID()
        reg.replaceAll([(pem: caA, host: "10.163.15.50:6443"), (pem: caB, host: "10.163.15.50:8443")], for: pid)
        let a = Self.der(reg.ca(for: "10.163.15.50:6443", profileID: pid))
        let b = Self.der(reg.ca(for: "10.163.15.50:8443", profileID: pid))
        #expect(a != nil && b != nil && a != b)
        #expect(Self.der(reg.ca(for: "10.163.15.50", profileID: pid)) == b)   // last writer

        // :8443 removed; :6443's PEM is now unparseable.
        reg.replaceAll([(pem: Self.broken, host: "10.163.15.50:6443")], for: pid)
        #expect(Self.der(reg.ca(for: "10.163.15.50:6443", profileID: pid)) == a)
        #expect(Self.der(reg.ca(for: "10.163.15.50", profileID: pid)) == a)   // the CONNECT lookup
    }

    @Test("a failed host with no CA of its own stays unpinned, whatever its bare host held")
    func noOwnCAStaysUnpinned() throws {
        let caB = try #require(try Self.selfSignedPEM("cluster-b"))
        let reg = ClusterCATrustRegistry(), pid = UUID()
        reg.replaceAll([(pem: caB, host: "10.163.15.50:8443")], for: pid)
        reg.replaceAll([(pem: Self.broken, host: "10.163.15.50:6443")], for: pid)
        #expect(reg.ca(for: "10.163.15.50", profileID: pid) == nil)
        #expect(reg.ca(for: "10.163.15.50:6443", profileID: pid) == nil)
    }

    @Test("a PEM that parsed keeps its bare alias over a failed neighbour's restore")
    func parsedAliasWins() throws {
        let caA = try #require(try Self.selfSignedPEM("cluster-a"))
        let caB = try #require(try Self.selfSignedPEM("cluster-b"))
        let reg = ClusterCATrustRegistry(), pid = UUID()
        reg.replaceAll([(pem: caA, host: "10.163.15.50:6443")], for: pid)
        let a = Self.der(reg.ca(for: "10.163.15.50:6443", profileID: pid))
        reg.replaceAll([(pem: Self.broken, host: "10.163.15.50:6443"), (pem: caB, host: "10.163.15.50:8443")], for: pid)
        let b = Self.der(reg.ca(for: "10.163.15.50:8443", profileID: pid))
        #expect(Self.der(reg.ca(for: "10.163.15.50:6443", profileID: pid)) == a)
        #expect(Self.der(reg.ca(for: "10.163.15.50", profileID: pid)) == b)
    }
}
