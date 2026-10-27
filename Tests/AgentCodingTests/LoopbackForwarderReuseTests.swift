import Foundation
import Testing
@testable import bromure_ac

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
        let owner = try #require(body.range(of: "guard owns(live.socketDevice, socketDevice) else {"))
        let retarget = try #require(body.range(of: "live.retarget(browserResponse: browserResponse)"))
        #expect(owner.lowerBound < retarget.lowerBound)
        let bind = try #require(body.range(of: "LoopbackCallbackForwarder(port: port"))
        #expect(retarget.lowerBound < bind.lowerBound)
        #expect(fwd.contains("if gen == generation { stop() }"))
        #expect(fwd.contains("let gen = generation, response = browserResponseOverride"))
        #expect(!fwd.contains("self?.relayFinished()"))
        // The workspace is fixed for the listener's life: retarget can't move it.
        #expect(!fwd.contains("self.socketDevice = socketDevice\n        browserResponseOverride"))
        #expect(!fwd.contains("func retarget(socketDevice"))
        #expect(fwd.components(separatedBy: "self.socketDevice = ").count == 2)   // init only
        for file in ["Sources/AgentCoding/BromureAC.swift", "Sources/AgentCoding/ClaudeRegistrationCoordinator.swift"] {
            let s = try Self.src(file)
            #expect(!s.contains("LoopbackCallbackForwarder(port"), "\(file) binds its own forwarder")
            #expect(!s.contains("LoopbackCallbackForwarder(\n"), "\(file) binds its own forwarder")
            // Through forPort -- directly, or the app's refusal gate.
            #expect(s.contains("LoopbackCallbackForwarder.forPort(") || s.contains("loopbackCallbackRefusal("))
        }
    }

    /// Finding (CWE-441): "A guest URL retargets another workspace's OAuth
    /// loopback forwarder". Any guest names a loopback port in a URL it opens;
    /// `forPort` handed it the live listener another workspace's sign-in was
    /// waiting on. Only the owning VM's own device may reuse it.
    @Test("only the workspace a listener relays into may reuse it")
    func ownership() {
        let a = NSObject(), b = NSObject()
        #expect(LoopbackCallbackForwarder.owns(a, a))
        #expect(!LoopbackCallbackForwarder.owns(a, b))          // another workspace
        #expect(!LoopbackCallbackForwarder.owns(nil, b))        // its workspace is gone: not adopted
    }

    /// Finding (CWE-441): "A refused loopback port still opens the sign-in,
    /// so another workspace receives the OAuth code". forPort refused, but the
    /// callers opened the authorize page anyway: the browser's redirect then
    /// reached the listener that holds the port -- another workspace's.
    @Test("a refused port never opens the sign-in page; a stopped VM lets its port go")
    func refusalBlocksTheOpen() throws {
        let ac = try Self.src("Sources/AgentCoding/BromureAC.swift")
        let reg = try Self.src("Sources/AgentCoding/ClaudeRegistrationCoordinator.swift")
        // Every guest-page open asks first, and returns when refused.
        for (name, text, open) in [("workspace", ac, "Self.openGuestRelayedURL(url)"),
                                   ("registration", reg, "ACAppDelegate.openGuestRelayedURL(url)")] {
            let gate = try #require(text.range(of: "loopbackCallbackRefusal(for: url, device: sandbox?.socketDevice")
                                    ?? text.range(of: "loopbackCallbackRefusal(\n                    for: url, device: sandbox?.socketDevice"),
                                    "\(name) doesn't ask")
            let after = text[gate.upperBound...]
            let ret = try #require(after.range(of: "return\n"))
            let opened = try #require(after.range(of: open))
            #expect(ret.lowerBound < opened.lowerBound, "\(name) opens before it gives up")
        }
        // Nobody else binds or reuses a callback listener (the debug sim aside).
        #expect(!reg.contains("LoopbackCallbackForwarder.forPort("))
        #expect(ac.components(separatedBy: "LoopbackCallbackForwarder.forPort(").count == 3)   // the gate + loopback-sim
        // A stopped VM's listeners stop with it; a workspace-less one frees its port.
        let unreg = try #require(ac.range(of: "func unregisterSession(_ id: Profile.ID) {"))
        let body = ac[unreg.upperBound...].prefix(500)
        let stop = try #require(body.range(of: "stopLoopbackForwarders(of: dev)"))
        let remove = try #require(body.range(of: "runningSessions.removeValue(forKey: id)"))
        #expect(stop.lowerBound < remove.lowerBound)
        let fwd = try Self.src("Sources/AgentCoding/LoopbackCallbackForwarder.swift")
        #expect(fwd.contains("for f in forwarders where f.isRunning && !f.hasWorkspace { f.stop() }"))
    }

    /// Finding (CWE-441): "Sign-in refusal ignores a [::1] redirect, so the
    /// other workspace still receives the OAuth code". The gate only knew
    /// 127.0.0.1 and localhost; a [::1] redirect (the forwarder listens there
    /// too) had no port, so no ownership check, and the page opened.
    @Test("every loopback spelling a browser follows is a callback port; nothing else is",
          arguments: ["http://127.0.0.1:1455/cb", "http://localhost:1455/cb", "http://[::1]:1455/cb",
                      "http://[0:0:0:0:0:0:0:1]:1455/cb", "http://[::ffff:127.0.0.1]:1455/cb",
                      "http://127.1:1455/cb", "http://2130706433:1455/cb", "http://0x7f000001:1455/cb",
                      "http://127.0.0.2:1455/cb", "http://0.0.0.0:1455/cb", "http://[::]:1455/cb",
                      "http://LOCALHOST.:1455/cb", "http://app.localhost:1455/cb"])
    @MainActor
    func loopbackRedirects(redirect: String) throws {
        var c = URLComponents(string: "https://auth.openai.com/oauth/authorize")!
        c.queryItems = [URLQueryItem(name: "client_id", value: "x"), URLQueryItem(name: "redirect_uri", value: redirect)]
        #expect(ACAppDelegate.loopbackCallbackPort(from: try #require(c.url)) == 1455, "\(redirect)")
    }

    @Test("a public or LAN redirect, or none, has no callback port",
          arguments: ["https://example.com:1455/cb", "http://192.168.1.4:1455/cb", "http://[fe80::1]:1455/cb",
                      "http://10.0.0.1:1455/cb", "http://notlocalhost:1455/cb", "http://[::2]:1455/cb",
                      "http://[::ffff:10.0.0.1]:1455/cb", "http://127.0.0.1/cb"])
    @MainActor
    func notLoopbackRedirects(redirect: String) throws {
        var c = URLComponents(string: "https://auth.openai.com/oauth/authorize")!
        c.queryItems = [URLQueryItem(name: "redirect_uri", value: redirect)]
        #expect(ACAppDelegate.loopbackCallbackPort(from: try #require(c.url)) == nil, "\(redirect)")
        #expect(ACAppDelegate.loopbackCallbackPort(from: URL(string: "https://auth.openai.com/oauth/authorize")!) == nil)
    }
}
