import Foundation
import Testing

/// A sign-in's loopback forwarder holds its host port until its relay closes
/// (or, abandoned, for its whole lifetime). A second sign-in on that port --
/// Codex always calls back on 1455; ac-e2e 33.5 reuses one port 40 times --
/// failed to bind ("couldn't bind 127.0.0.1:<port>") and, in the app, left
/// the OLD forwarder relaying the browser's callback into the old workspace.
/// Every site now goes through `forPort`, which retargets a live forwarder.
@Suite("Loopback forwarders: one per port, handed to the newest sign-in")
struct LoopbackForwarderReuseTests {
    static let top = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    static func src(_ p: String) throws -> String { try String(contentsOf: top.appendingPathComponent(p), encoding: .utf8) }

    @Test("no site binds a second forwarder for a port; a superseded relay can't stop the new one")
    func wiring() throws {
        let fwd = try Self.src("Sources/AgentCoding/LoopbackCallbackForwarder.swift")
        let forPort = try #require(fwd.range(of: "static func forPort("))
        let body = fwd[forPort.upperBound...].prefix(900)
        let retarget = try #require(body.range(of: "live.retarget(socketDevice: socketDevice, browserResponse: browserResponse)"))
        let bind = try #require(body.range(of: "LoopbackCallbackForwarder(port: port"))
        #expect(retarget.lowerBound < bind.lowerBound)
        #expect(fwd.contains("if gen == generation { stop() }"))
        #expect(fwd.contains("let gen = generation, response = browserResponseOverride"))
        #expect(!fwd.contains("self?.relayFinished()"))
        for file in ["Sources/AgentCoding/BromureAC.swift", "Sources/AgentCoding/ClaudeRegistrationCoordinator.swift"] {
            let s = try Self.src(file)
            #expect(!s.contains("LoopbackCallbackForwarder(port"), "\(file) binds its own forwarder")
            #expect(!s.contains("LoopbackCallbackForwarder(\n"), "\(file) binds its own forwarder")
            #expect(s.contains("LoopbackCallbackForwarder.forPort("))
        }
    }
}
