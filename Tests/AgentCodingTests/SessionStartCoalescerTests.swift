import Foundation
import os
import Testing
@testable import bromure_ac

/// Board report: over a slow link the window doesn't move for a while after
/// Send, and the clicks that follow each started an identical session.
@Suite("New session: the same start twice is one session", .serialized)
struct SessionStartCoalescerTests {
    private func key(_ message: String = "fix the tests") -> String {
        SessionStartCoalescer.key(profile: "P", tool: "claude", cwd: "~", cloneURL: nil, message: message,
                                  instructions: nil, room: nil, attachments: [])
    }

    /// A clock the test moves; read from any thread.
    private final class Clock: @unchecked Sendable {
        private let lock = OSAllocatedUnfairLock(initialState: Date())
        var now: Date { lock.withLock { $0 } }
        func advance(_ s: TimeInterval) { lock.withLock { $0 += s } }
    }

    @Test("again within 10 s of its start: the first's session; after, or different, a new one")
    func window() {
        let c = SessionStartCoalescer()
        let clock = Clock()
        var started = 0
        func start(_ k: String) -> String? {
            c.run(k, now: { clock.now }) { started += 1; return ["ok": true, "id": "S\(started)"] }["id"] as? String
        }
        #expect(start(key()) == "S1")
        clock.advance(3)
        #expect(start(key()) == "S1")   // Send clicked again
        #expect(start(key("something else")) == "S2")
        clock.advance(11)
        #expect(start(key()) == "S3")   // a deliberate second one, later
        #expect(started == 3)
        // "~", "" and "~/" are the same folder; surrounding blanks don't count.
        #expect(SessionStartCoalescer.key(profile: "p", tool: "claude", cwd: "", cloneURL: nil, message: " fix the tests ",
                                          instructions: nil, room: nil, attachments: []) == key())
    }

    @Test("a start that failed isn't remembered: the retry goes through")
    func failureNotRemembered() {
        let c = SessionStartCoalescer()
        var calls = 0
        _ = c.run(key()) { calls += 1; return ["error": "no machine"] }
        let r = c.run(key()) { calls += 1; return ["ok": true, "id": "S"] }
        #expect(calls == 2 && r["id"] as? String == "S")
    }

    /// Review: a second Send 11 s into a minute-long start (an attached
    /// machine's) didn't wait, started another session, and the first's
    /// completion was written on the second's slot.
    @Test("a Send while the first still starts — however long it takes — waits, and gets its session")
    func pendingIsWaitedFor() async {
        let c = SessionStartCoalescer()
        let clock = Clock()
        let k = key()
        let gate = DispatchSemaphore(value: 0)
        let counter = OSAllocatedUnfairLock(initialState: 0)
        @Sendable func work() -> [String: Any] {
            let n = counter.withLock { $0 += 1; return $0 }
            gate.wait()
            return ["ok": true, "id": "S\(n)"]
        }
        let first = Task.detached { c.run(k, now: { clock.now }, work)["id"] as? String }
        try? await Task.sleep(nanoseconds: 100_000_000)
        clock.advance(11)   // the machine is slow
        let second = Task.detached { c.run(k, now: { clock.now }, work)["id"] as? String }
        try? await Task.sleep(nanoseconds: 100_000_000)
        gate.signal()
        let a = await first.value, b = await second.value
        #expect(a == "S1" && b == "S1")
        #expect(counter.withLock { $0 } == 1)
    }

    /// Review: after a long failed start the retry's slot was stamped with
    /// the time before it waited — already "old" — so the next identical
    /// Send didn't wait for the retry and started a second session.
    @Test("after a failed start, the retry is waited for by the next Send too")
    func retryAfterFailureIsWaitedFor() async {
        let c = SessionStartCoalescer()
        let clock = Clock()
        let k = key()
        let failGate = DispatchSemaphore(value: 0), okGate = DispatchSemaphore(value: 0)
        let counter = OSAllocatedUnfairLock(initialState: 0)
        let a = Task.detached { c.run(k, now: { clock.now }) {
            counter.withLock { $0 += 1 }; failGate.wait(); return ["error": "timed out"] } }
        try? await Task.sleep(nanoseconds: 100_000_000)
        let b = Task.detached { c.run(k, now: { clock.now }) {
            counter.withLock { $0 += 1 }; okGate.wait(); return ["ok": true, "id": "B"] }["id"] as? String }
        try? await Task.sleep(nanoseconds: 100_000_000)
        clock.advance(50)
        failGate.signal()   // A fails; B (waiting) becomes the retry
        try? await Task.sleep(nanoseconds: 200_000_000)
        let third = Task.detached { c.run(k, now: { clock.now }) {
            counter.withLock { $0 += 1 }; return ["ok": true, "id": "C"] }["id"] as? String }
        try? await Task.sleep(nanoseconds: 100_000_000)
        okGate.signal()
        _ = await a.value
        let rb = await b.value, rc = await third.value
        #expect(rb == "B" && rc == "B")
        #expect(counter.withLock { $0 } == 2)
    }

    @Test("a start that can't wait: dropped while the same one runs; its reply, id and all, answers the rest")
    func claim() {
        let c = SessionStartCoalescer()
        let now = Date()
        let t1 = c.claim(key(), now: now)
        #expect(t1 != nil)
        #expect(c.claim(key(), now: now + 30) == nil)   // still under way
        c.finish(key(), token: t1!, reply: nil, now: now + 31)   // it failed: a retry may go
        let t2 = c.claim(key(), now: now + 32)
        #expect(t2 != nil)
        // A stale finish (the first, again) can't touch the new attempt.
        c.finish(key(), token: t1!, reply: nil, now: now + 33)
        #expect(c.claim(key(), now: now + 33) == nil)
        c.finish(key(), token: t2!, reply: ["ok": true, "id": "M"], now: now + 34)
        // A client's same start through the hub gets the session's id.
        let r = c.run(key(), now: { now + 36 }) { ["ok": true, "id": "other"] }
        #expect(r["id"] as? String == "M")
    }

    @Test("the composer's file and a client's same file make the same key")
    func attachmentsMatch() {
        let data = Data("hello".utf8)
        let wire: [String: Any] = ["name": "a.txt", "data": data.base64EncodedString(), "isImage": false]
        #expect(SessionStartCoalescer.attachment(wire: wire) == SessionStartCoalescer.attachment(name: "a.txt", bytes: data.count))
    }
}
