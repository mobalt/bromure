import Foundation
import Network
import os
import Testing
@testable import bromure_ac

/// Board report: on a train the fat client lost its P2P link and never got it
/// back on its own — closing the window and connecting again did. A dropout
/// with no reset leaves the signaling socket half-open: it still read
/// "connected", its pings simply never completed, and every re-establish sent
/// its offer into it and heard nothing back.
@Suite("P2P device channel: a silent socket is noticed", .serialized)
struct P2PDeviceChannelLivenessTests {
    /// A local WebSocket server that counts accepted connections and either
    /// answers pings or — a half-open link — swallows them.
    private final class Server: @unchecked Sendable {
        let listener: NWListener
        private let accepted = OSAllocatedUnfairLock(initialState: 0)
        private var conns: [NWConnection] = []
        private let queue = DispatchQueue(label: "test.ws-server")
        var count: Int { accepted.withLock { $0 } }

        init(answersPings: Bool) throws {
            let ws = NWProtocolWebSocket.Options()
            ws.autoReplyPing = answersPings
            let params = NWParameters.tcp
            params.defaultProtocolStack.applicationProtocols.insert(ws, at: 0)
            listener = try NWListener(using: params, on: .any)
            listener.newConnectionHandler = { [weak self] c in
                guard let self else { return }
                self.accepted.withLock { $0 += 1 }
                self.conns.append(c)
                c.start(queue: self.queue)
                self.drain(c)
            }
        }

        /// Keep reading so the socket stays open (and pings arrive).
        private func drain(_ c: NWConnection) {
            c.receiveMessage { [weak self] _, _, _, error in
                if error == nil { self?.drain(c) }
            }
        }

        func start() async -> Int {
            listener.start(queue: queue)
            for _ in 0..<100 {
                if let p = listener.port?.rawValue, p != 0 { return Int(p) }
                try? await Task.sleep(nanoseconds: 20_000_000)
            }
            return 0
        }

        func stop() {
            listener.cancel()
            queue.sync { conns.forEach { $0.cancel() } }
        }
    }

    private func channel(port: Int) throws -> DeviceChannel {
        let ch = DeviceChannel(endpoint: try ControlPlaneEndpoint(base: "http://127.0.0.1:\(port)"), token: "t")
        ch.pingInterval = 0.4
        ch.pongTimeout = 0.6
        return ch
    }

    private func waitFor(_ seconds: TimeInterval, _ cond: () -> Bool) async -> Bool {
        let end = Date().addingTimeInterval(seconds)
        while Date() < end {
            if cond() { return true }
            try? await Task.sleep(nanoseconds: 50_000_000)
        }
        return cond()
    }

    @Test("pings that never come back drop the socket and open a new one")
    func unansweredPingReconnects() async throws {
        let server = try Server(answersPings: false)
        let port = await server.start()
        #expect(port > 0)
        let ch = try channel(port: port)
        ch.connect()
        defer { ch.close(); server.stop() }
        #expect(await waitFor(5) { ch.connected })
        // First ping at 0.4 s, its deadline at 1.0 s, a reconnect ~0.5 s later.
        #expect(await waitFor(6) { server.count >= 2 })
    }

    @Test("a socket whose pings are answered stays")
    func answeredPingStays() async throws {
        let server = try Server(answersPings: true)
        let port = await server.start()
        let ch = try channel(port: port)
        ch.connect()
        defer { ch.close(); server.stop() }
        #expect(await waitFor(5) { ch.connected })
        try? await Task.sleep(nanoseconds: 3_000_000_000)   // several ping rounds
        #expect(server.count == 1)
        #expect(ch.connected)
    }

    @Test("recycle opens a fresh socket — but not one just opened")
    func recycle() async throws {
        let server = try Server(answersPings: true)
        let port = await server.start()
        let ch = try channel(port: port)
        ch.connect()
        defer { ch.close(); server.stop() }
        #expect(await waitFor(5) { ch.connected })
        ch.recycle()   // fresh (under recycleMinAge): kept
        try? await Task.sleep(nanoseconds: 1_000_000_000)
        #expect(server.count == 1)
        ch.recycleMinAge = 0
        ch.recycle()
        #expect(await waitFor(5) { server.count == 2 && ch.connected })
    }

    @Test("an establish that heard nothing from the peer suspects the channel; one that did, doesn't")
    func recycleStage() {
        #expect(P2PBroker.recyclesChannel(after: .signaling))
        #expect(!P2PBroker.recyclesChannel(after: .ice))
        #expect(!P2PBroker.recyclesChannel(after: .transport))
    }
}
