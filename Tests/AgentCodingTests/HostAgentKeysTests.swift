import Foundation
import Testing
@testable import bromure_ac

/// Keys picked out of a host ssh-agent (a YubiKey behind gpg-agent, say):
/// the VM sees and signs with the picked keys only, never the agent's
/// others. A real `ssh-agent` holding two keys stands in for the host one.
@Suite("Host agent keys", .serialized)
struct HostAgentKeysTests {

    /// A throwaway `ssh-agent -D` loaded with two fresh ed25519 keys.
    final class Fixture {
        let dir: URL
        let socket: String
        let agent: Process
        /// OpenSSH public-key lines, "picked" then "other".
        let picked: String
        let other: String

        init() throws {
            dir = URL(fileURLWithPath: NSTemporaryDirectory())
                .appendingPathComponent("hak-\(UUID().uuidString.prefix(8))")
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            socket = dir.appendingPathComponent("a.sock").path
            agent = Process()
            agent.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-agent")
            agent.arguments = ["-D", "-a", socket]
            agent.standardOutput = FileHandle.nullDevice
            agent.standardError = FileHandle.nullDevice
            try agent.run()
            let deadline = Date().addingTimeInterval(2)
            while !FileManager.default.fileExists(atPath: socket) && Date() < deadline {
                Thread.sleep(forTimeInterval: 0.01)
            }
            var lines: [String] = []
            for name in ["picked", "other"] {
                let key = dir.appendingPathComponent(name).path
                try Self.run("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", name, "-f", key])
                try Self.run("/usr/bin/ssh-add", ["-q", key], env: ["SSH_AUTH_SOCK": socket])
                lines.append(try String(contentsOfFile: key + ".pub", encoding: .utf8)
                    .trimmingCharacters(in: .whitespacesAndNewlines))
            }
            picked = lines[0]
            other = lines[1]
        }

        deinit {
            agent.terminate()
            try? FileManager.default.removeItem(at: dir)
        }

        static func run(_ exe: String, _ args: [String], env: [String: String] = [:]) throws {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: exe)
            p.arguments = args
            p.environment = ProcessInfo.processInfo.environment.merging(env) { $1 }
            p.standardOutput = FileHandle.nullDevice
            p.standardError = FileHandle.nullDevice
            try p.run()
            p.waitUntilExit()
            guard p.terminationStatus == 0 else {
                throw NSError(domain: "test", code: Int(p.terminationStatus))
            }
        }
    }

    // MARK: - Wire helpers (the VM side of the vsock bridge)

    static func blob(_ line: String) -> Data {
        Data(base64Encoded: String(line.split(separator: " ")[1]))!
    }

    static func string(_ d: Data) -> Data {
        var be = UInt32(d.count).bigEndian
        return Data(bytes: &be, count: 4) + d
    }

    static func roundTrip(_ fd: Int32, _ payload: Data) -> Data? {
        let frame = string(payload)
        _ = frame.withUnsafeBytes { write(fd, $0.baseAddress!, frame.count) }
        func readN(_ n: Int) -> Data? {
            var buf = [UInt8](repeating: 0, count: n); var got = 0
            while got < n {
                let r = buf.withUnsafeMutableBufferPointer { read(fd, $0.baseAddress! + got, n - got) }
                if r <= 0 { return nil }
                got += r
            }
            return Data(buf)
        }
        guard let len = readN(4) else { return nil }
        return readN(len.reduce(0) { $0 << 8 | Int($1) })
    }

    /// Identity blobs out of an IDENTITIES_ANSWER.
    static func blobs(in answer: Data) -> [Data] {
        var cursor = 1
        func u32() -> Int { defer { cursor += 4 }; return answer[cursor..<cursor + 4].reduce(0) { $0 << 8 | Int($1) } }
        func str() -> Data { let n = u32(); defer { cursor += n }; return answer.subdata(in: cursor..<cursor + n) }
        return (0..<u32()).map { _ in let b = str(); _ = str(); return b }
    }

    /// Serve one VM connection on a socketpair, return the VM end.
    static func connect(_ server: SSHAgentServer, profileID: UUID) -> Int32 {
        var fds: [Int32] = [0, 0]
        socketpair(AF_UNIX, SOCK_STREAM, 0, &fds)
        let serverFD = fds[0]
        Task.detached { await server.serve(fd: serverFD, profileID: profileID) }
        return fds[1]
    }

    // MARK: - Tests

    @Test("The VM sees only the picked key, and signs with it through the host agent")
    func pickedKeyOnly() throws {
        let fx = try Fixture()
        let server = SSHAgentServer(consent: ConsentBroker())
        let profile = UUID()
        server.setHostAgentKeys([Self.blob(fx.picked): fx.socket], for: profile)
        let fd = Self.connect(server, profileID: profile)
        defer { close(fd) }

        let answer = try #require(Self.roundTrip(fd, Data([11])))
        #expect(answer.first == 12)
        #expect(Self.blobs(in: answer) == [Self.blob(fx.picked)])

        let signPicked = Data([13]) + Self.string(Self.blob(fx.picked))
            + Self.string(Data("challenge".utf8)) + Data([0, 0, 0, 0])
        #expect(Self.roundTrip(fd, signPicked)?.first == 14)

        // The agent holds "other" too, but it wasn't picked: no signature.
        let signOther = Data([13]) + Self.string(Self.blob(fx.other))
            + Self.string(Data("challenge".utf8)) + Data([0, 0, 0, 0])
        #expect(Self.roundTrip(fd, signOther)?.first == 5)
    }

    @Test("Another workspace gets none of the picked keys")
    func otherWorkspaceIsolated() throws {
        let fx = try Fixture()
        let server = SSHAgentServer(consent: ConsentBroker())
        server.setHostAgentKeys([Self.blob(fx.picked): fx.socket], for: UUID())
        let fd = Self.connect(server, profileID: UUID())
        defer { close(fd) }

        let answer = try #require(Self.roundTrip(fd, Data([11])))
        #expect(Self.blobs(in: answer).isEmpty)
        let sign = Data([13]) + Self.string(Self.blob(fx.picked))
            + Self.string(Data("challenge".utf8)) + Data([0, 0, 0, 0])
        #expect(Self.roundTrip(fd, sign)?.first == 5)
    }

    @Test("Listing a host agent yields addable keys that point back at it")
    func listHostAgentKeys() throws {
        let fx = try Fixture()
        let keys = try ACAppDelegate.listHostAgentKeys(socket: fx.socket)
        #expect(Set(keys.map(\.label)) == ["picked", "other"])
        for key in keys {
            #expect(key.hostAgentSocket == fx.socket)
            #expect(key.filename.isEmpty)
            #expect(key.publicKeyText.hasPrefix("ssh-ed25519 "))
        }
        #expect(keys.contains { $0.publicKeyText == fx.picked })
    }

    @Test("A missing socket is an error, not an empty list")
    func missingSocket() {
        #expect(throws: (any Error).self) {
            try ACAppDelegate.listHostAgentKeys(socket: "/nonexistent/agent.sock")
        }
    }

    @Test("hostAgentSocket round-trips through JSON; file keys don't grow the field")
    func codable() throws {
        let hw = ImportedSSHKey(label: "yubikey", filename: "",
                                publicKeyText: "ssh-ed25519 AAAA cardno:1",
                                hostAgentSocket: "~/.gnupg/S.gpg-agent.ssh")
        let back = try JSONDecoder().decode(ImportedSSHKey.self, from: JSONEncoder().encode(hw))
        #expect(back == hw)
        #expect(back.isFromHostAgent)

        let file = ImportedSSHKey(label: "f", filename: "x-id_ed25519")
        let json = String(data: try JSONEncoder().encode(file), encoding: .utf8)!
        #expect(!json.contains("hostAgentSocket"))
        #expect(try JSONDecoder().decode(ImportedSSHKey.self, from: Data(json.utf8)).hostAgentSocket == nil)
    }

    @Test("\"\" resolves to SSH_AUTH_SOCK, ~ to the home folder")
    func resolveSocket() {
        #expect(HostAgentClient.resolveHostSocket("") == ProcessInfo.processInfo.environment["SSH_AUTH_SOCK"].flatMap { $0.isEmpty ? nil : $0 })
        #expect(HostAgentClient.resolveHostSocket("~/a.sock")
                == FileManager.default.homeDirectoryForCurrentUser.path + "/a.sock")
    }
}
