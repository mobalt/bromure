import Foundation
import Darwin

/// Where the agents' `bromure-delegation` MCP streams meet the Bromure AC
/// that serves them. Each agent's MCP shim (`__mcp-delegation`) connects to
/// delegation.sock and says `bromure-hello w<window>`; a connected Bromure
/// AC keeps a `delegation-mcp` SSH channel parked here (see the shared
/// RemoteSSHHandlers), and the hub splices the next stream into it — the
/// delegation engine and every record live on that Mac. With no Bromure AC
/// connected, a stream is answered here: the tool list, and a plain "not
/// connected" from each call. When a channel parks later, one such stream is
/// dropped so its shim reconnects and lands on the relay.
final class DelegationHub: @unchecked Sendable {
    static let shared = DelegationHub()

    static var socketPath: String { AgentHostPaths.support.appendingPathComponent("delegation.sock").path }

    private let lock = NSLock()
    /// Parked SSH channels, newest last. `alive`, when the parker can say,
    /// lets a park drop the dead ones beneath it: handing out goes newest
    /// first, so an old dead one would never be reached, and its waiting
    /// thread and link would stay forever.
    private var offers: [(take: (Int32) -> Bool, alive: (() -> Bool)?)] = []
    /// Streams answered locally, oldest first.
    private var fallbacks: [Int32] = []
    /// A Bromure AC has parked a channel here since this Sidecar started:
    /// a stream answered locally then is a relay gap (a link reconnecting),
    /// not "no Bromure AC at all".
    private var everParked = false
    /// How long a call on the local fallback waits for a relay to park (a
    /// link redialling after a drop) before it's refused.
    static let relayGrace: TimeInterval = 20
    /// The first line the local fallback sends: the shim learns its stream
    /// reaches no Bromure AC — whatever it held there was never done, and
    /// is safe to send again once a relay is back.
    static let localMarker = "bromure-local"

    // MARK: Parked channels (the SSH server's resolver)

    /// `offer` takes a stream (true) or declines it (false: its channel died
    /// while parked). Given `alive`, a dead offer is also handed -1 when a
    /// later park prunes it, and must decline it — that releases its waiter.
    func park(_ offer: @escaping @Sendable (Int32) -> Bool, alive: (@Sendable () -> Bool)? = nil) {
        lock.lock()
        var dead: [(Int32) -> Bool] = []
        offers.removeAll { o in
            guard let alive = o.alive, !alive() else { return false }
            dead.append(o.take)
            return true
        }
        let wasEmpty = offers.isEmpty
        let first = !everParked
        everParked = true
        offers.append((offer, alive))
        let kick = fallbacks.isEmpty ? nil : fallbacks.removeFirst()
        lock.unlock()
        if first { AgentHostLog.log("delegation: a Bromure AC relay is parked") }
        else if wasEmpty, kick != nil { AgentHostLog.log("delegation: a Bromure AC relay is back") }
        for d in dead { _ = d(-1) }
        // Its shim reconnects at once — onto the channel just parked.
        if let kick { shutdown(kick, SHUT_RDWR) }
    }

    /// Offers waiting (tests).
    var parkedCount: Int { lock.lock(); defer { lock.unlock() }; return offers.count }

    /// Whether a relay parks within `grace` (polled; a park also shuts the
    /// waiting fallback stream down, which is the same answer).
    func waitForRelay(within grace: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(grace)
        while Date() < deadline {
            if parkedCount > 0 { return true }
            Thread.sleep(forTimeInterval: 0.25)
        }
        return parkedCount > 0
    }

    var hadRelay: Bool { lock.lock(); defer { lock.unlock() }; return everParked }

    /// Hand `fd` to a live parked channel; false when there is none.
    private func relay(_ fd: Int32) -> Bool {
        while true {
            lock.lock()
            guard let offer = offers.popLast() else { lock.unlock(); return false }
            lock.unlock()
            if offer.take(fd) { return true }   // else that channel died while parked
        }
    }

    // MARK: The agents' side

    func start() throws {
        let path = Self.socketPath
        unlink(path)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw HostError.failed("delegation socket") }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        withUnsafeMutableBytes(of: &addr.sun_path) { buf in
            for (i, b) in bytes.enumerated() where i < buf.count - 1 { buf[i] = b }
        }
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard rc == 0, listen(fd, 32) == 0 else { close(fd); throw HostError.failed("bind \(path)") }
        chmod(path, 0o600)
        Thread.detachNewThread { [weak self] in
            while true {
                let c = accept(fd, nil, nil)
                if c < 0 { if errno == EINTR { continue }; return }
                var one: Int32 = 1
                setsockopt(c, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
                guard let self else { close(c); return }
                if self.relay(c) { continue }   // the SSH channel owns it now
                self.lock.lock(); self.fallbacks.append(c); self.lock.unlock()
                Thread.detachNewThread { [weak self] in
                    Self.serveLocally(c)
                    self?.lock.lock()
                    self?.fallbacks.removeAll { $0 == c }
                    self?.lock.unlock()
                    close(c)
                }
            }
        }
        AgentHostLog.log("delegation: listening on \(path)")
    }

    // MARK: No Bromure AC connected

    private static let notConnected = "No Bromure AC is connected to this Mac right now, so other agents can't be reached. Delegation works while Bromure Agentic Coding has this Mac's window open — tell your user."
    /// A relay was here and hasn't come back within the grace: the link is
    /// down or reconnecting — not "no Bromure AC".
    private static let reconnecting = "The link to Bromure AC dropped and hasn't come back yet (it usually does within a minute) — wait a moment and retry. If it keeps failing, Bromure AC may have closed: tell your user."

    /// Answer a stream here: enough MCP for Claude to know the tools, and a
    /// clear refusal from every call.
    private static func serveLocally(_ fd: Int32) {
        ControlServer.writeAll(fd, Data((localMarker + "\n").utf8))
        var buf = [UInt8](repeating: 0, count: 65536)
        var pending = Data()
        var sawHello = false
        while true {
            let n = read(fd, &buf, buf.count)
            if n <= 0 { return }
            pending.append(contentsOf: buf[0..<n])
            while let nl = pending.firstIndex(of: 0x0A) {
                let lineData = Data(pending[pending.startIndex..<nl])
                pending = Data(pending[(nl + 1)...])
                if !sawHello { sawHello = true; continue }   // bromure-hello w<N>
                guard let msg = (try? JSONSerialization.jsonObject(with: lineData)) as? [String: Any] else { continue }
                // A call: a relay may be on its way back (a link redialling) —
                // hold it, and if one parks, end this stream unanswered: the
                // shim sends it again over the relay (nothing here did it).
                if msg["method"] as? String == "tools/call", msg["id"] != nil {
                    AgentHostLog.log("delegation: a call with no Bromure AC relay — holding it up to \(Int(relayGrace)) s")
                    if shared.waitForRelay(within: relayGrace) {
                        AgentHostLog.log("delegation: relay back — the call goes to it")
                        return
                    }
                    AgentHostLog.log("delegation: no relay after \(Int(relayGrace)) s — refused")
                }
                guard let reply = answer(msg),
                      let out = try? JSONSerialization.data(withJSONObject: reply) else { continue }
                ControlServer.writeAll(fd, out + Data([0x0A]))
            }
        }
    }

    private static func answer(_ msg: [String: Any]) -> [String: Any]? {
        let id = msg["id"]
        guard let id else { return nil }   // notifications
        func result(_ r: Any) -> [String: Any] { ["jsonrpc": "2.0", "id": id, "result": r] }
        switch msg["method"] as? String ?? "" {
        case "initialize":
            return result([
                "protocolVersion": "2025-03-26",
                "serverInfo": ["name": "bromure-delegation", "version": "1.1.0"],
                "capabilities": ["tools": ["listChanged": false]],
                "instructions": DelegationMCPCatalog.instructions,
            ])
        case "ping":
            return result([String: Any]())
        case "tools/list":
            return result(["tools": DelegationMCPCatalog.tools])
        case "tools/call":
            let text = shared.hadRelay ? reconnecting : notConnected
            return result(["content": [["type": "text", "text": text]], "isError": true])
        default:
            return ["jsonrpc": "2.0", "id": id,
                    "error": ["code": -32601, "message": "Method not found"]]
        }
    }
}

/// `bromure-sidecar __mcp-delegation`: the stdio MCP server Claude runs.
/// Pipes stdio to delegation.sock, announcing its tmux window first, and
/// reconnects (announcing again) whenever the socket drops — the stream
/// moves between the local fallback and a Bromure AC's relay that way,
/// without Claude noticing. bromure-agentd's python shim, in Swift.
enum DelegationShim {
    static func run() -> Int32 {
        let hello: String = {
            guard let pane = ProcessInfo.processInfo.environment["TMUX_PANE"], !pane.isEmpty else { return "w-1" }
            let r = Tmux.run(["display-message", "-p", "-t", pane, "w#{window_index}"], timeout: 5)
            let w = r.out.trimmingCharacters(in: .whitespacesAndNewlines)
            return w.hasPrefix("w") ? w : "w-1"
        }()
        signal(SIGPIPE, SIG_IGN)
        let lock = NSLock()
        var sock: Int32 = -1
        var stdinOpen = true

        func connectHub() -> Int32 {
            var delay = 0.2
            while true {
                let fd = socket(AF_UNIX, SOCK_STREAM, 0)
                var addr = sockaddr_un()
                addr.sun_family = sa_family_t(AF_UNIX)
                let bytes = Array(DelegationHub.socketPath.utf8)
                withUnsafeMutableBytes(of: &addr.sun_path) { buf in
                    for (i, b) in bytes.enumerated() where i < buf.count - 1 { buf[i] = b }
                }
                let ok = withUnsafePointer(to: &addr) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
                    }
                }
                if ok == 0 {
                    ControlServer.writeAll(fd, Data("bromure-hello \(hello)\n".utf8))
                    return fd
                }
                close(fd)
                Thread.sleep(forTimeInterval: delay)
                delay = min(delay * 2, 5)
            }
        }

        // In-flight calls (JSON-RPC requests not answered yet), with the
        // stream they went out on. A stream answered by the hub's local
        // fallback did nothing: what it held is sent again once a relay is
        // back. A relay stream that drops — or falls silent past a call's
        // deadline — may have done it or not: those calls get an error
        // reply, never silence (Claude waited for a reply until its own
        // 30-minute limit, a `wait` well past its timeout).
        var pending = DelegationShimCalls()
        var generation = 0
        var localGenerations: Set<Int> = []

        func current() -> (fd: Int32, gen: Int) {
            lock.lock(); defer { lock.unlock() }
            if sock < 0 { sock = connectHub(); generation += 1 }
            return (sock, generation)
        }

        // One writer at a time (stdin's lines, the reader's resends), and a
        // stream is never closed — nor its fd number reused by the next one —
        // between the "still the current stream?" check and the write.
        let writeLock = NSLock()

        func drop(_ fd: Int32) {
            writeLock.lock()
            lock.lock()
            if sock == fd { close(fd); sock = -1 }
            lock.unlock()
            writeLock.unlock()
        }

        /// Write `data` on stream `gen`, recording it as in flight there.
        /// A failed write takes the record back so the caller sends it again
        /// — unless the reader took it first (the stream's end): then the
        /// reader owns it (sends it again, or reports it lost), never both.
        enum Sent { case sent, retry, ownedByReader }
        func send(_ data: Data, _ fd: Int32, _ gen: Int) -> Sent {
            writeLock.lock(); defer { writeLock.unlock() }
            lock.lock()
            let live = sock == fd && generation == gen
            if live { pending.sent(data, on: gen) }
            lock.unlock()
            guard live else { return .retry }
            if writeLine(data, fd) { return .sent }
            lock.lock(); defer { lock.unlock() }
            guard let key = DelegationShimCalls.requestKey(data) else { return .retry }   // not a call: just again
            return pending.take(key: key) != nil ? .retry : .ownedByReader
        }

        func writeLine(_ data: Data, _ fd: Int32) -> Bool {
            data.withUnsafeBytes { raw -> Bool in
                var base = raw.baseAddress!, rem = raw.count
                while rem > 0 {
                    let w = write(fd, base, rem)
                    if w <= 0 { return false }
                    base += w; rem -= w
                }
                return true
            }
        }

        let out = NSLock()
        func emit(_ line: Data) {
            out.lock(); FileHandle.standardOutput.write(line); out.unlock()
        }

        // stdin → hub, one line at a time (a line never splits across two
        // connections).
        Thread.detachNewThread {
            while let line = readLine(strippingNewline: false) {
                let data = Data(line.utf8)
                while true {
                    let (fd, gen) = current()
                    let r = send(data, fd, gen)
                    if r != .retry { break }
                    drop(fd)
                }
            }
            lock.lock(); stdinOpen = false; let fd = sock; lock.unlock()
            if fd >= 0 { shutdown(fd, SHUT_WR) }
        }

        // A relay that falls silent (no EOF: a half-dead link) holds its
        // calls for ever: past a call's deadline, the stream counts as lost.
        Thread.detachNewThread {
            while true {
                Thread.sleep(forTimeInterval: 2)
                lock.lock()
                let overdue = pending.overdue(now: Date()).filter { !localGenerations.contains($0.gen) }
                let fd = sock, gen = generation
                // On a stream already gone (it died while held calls were being
                // sent again): nobody reads it any more — answer them here.
                // Only those still pending: one the reader settled meanwhile
                // already has its reply.
                let orphans = overdue.filter { $0.gen != gen || fd < 0 }.compactMap { pending.take(key: $0.key) }
                lock.unlock()
                for o in orphans { emit(DelegationShimCalls.lostReply(o)) }
                guard fd >= 0, let late = overdue.first(where: { $0.gen == gen }) else { continue }
                AgentHostLog.log("delegation: no reply to \(late.label) within \(Int(late.limit)) s — dropping the relay stream")
                shutdown(fd, SHUT_RDWR)   // the reader sees EOF: its lost calls get errors
            }
        }

        // hub → stdout, a line at a time.
        var buf = [UInt8](repeating: 0, count: 65536)
        var partial = Data()
        while true {
            let (fd, gen) = current()
            let n = read(fd, &buf, buf.count)
            if n > 0 {
                partial.append(contentsOf: buf[0..<n])
                while let nl = partial.firstIndex(of: 0x0A) {
                    let line = Data(partial[partial.startIndex...nl])
                    partial = Data(partial[(nl + 1)...])
                    if String(decoding: line, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                        == DelegationHub.localMarker {
                        lock.lock(); localGenerations.insert(gen); lock.unlock()
                        continue
                    }
                    lock.lock(); pending.answered(line); lock.unlock()
                    emit(line)
                }
                continue
            }
            partial = Data()
            drop(fd)
            lock.lock()
            let wasLocal = localGenerations.contains(gen)
            let held = pending.take(gen: gen)
            let open = stdinOpen
            lock.unlock()
            if wasLocal {
                // Never done: again, over whatever the hub hands out now.
                if !held.isEmpty {
                    AgentHostLog.log("delegation: \(held.count) held call(s) go to the relay")
                    var rest = held
                    while let h = rest.first {
                        let (nfd, ngen) = current()
                        if send(h.line, nfd, ngen) != .retry { rest.removeFirst() } else { drop(nfd) }
                    }
                }
            } else {
                for h in held { emit(DelegationShimCalls.lostReply(h)) }
                if !held.isEmpty { AgentHostLog.log("delegation: relay stream lost with \(held.count) call(s) under way") }
            }
            if !open { return 0 }
            Thread.sleep(forTimeInterval: 0.2)
        }
    }
}
