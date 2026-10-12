import Foundation
import os
import Testing
@testable import bromure_ac

/// Board report: over a slow link the window doesn't move for a while after
/// Send, and the clicks that follow each started an identical session.
@Suite("New session: the same start twice is one session")
struct SessionStartCoalescerTests {
    private func key(_ message: String = "fix the tests") -> String {
        SessionStartCoalescer.key(profile: "P", tool: "claude", cwd: "~", cloneURL: nil, message: message,
                                  instructions: nil, room: nil, attachments: [])
    }

    @Test("again within 10 s: the first's session; after, or different, a new one")
    func window() {
        let c = SessionStartCoalescer()
        var started = 0
        var now = Date()
        func start(_ k: String) -> String? {
            c.run(k, now: { now }) { started += 1; return ["ok": true, "id": "S\(started)"] }["id"] as? String
        }
        #expect(start(key()) == "S1")
        now += 3
        #expect(start(key()) == "S1")   // Send clicked again
        #expect(start(key("something else")) == "S2")
        now += 11
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

    @Test("a second Send while the first still starts waits for it, and gets its session")
    func pendingIsWaitedFor() async {
        let c = SessionStartCoalescer()
        let k = key()
        let gate = DispatchSemaphore(value: 0)
        let counter = OSAllocatedUnfairLock(initialState: 0)
        @Sendable func work() -> [String: Any] {
            counter.withLock { $0 += 1 }
            gate.wait()
            return ["ok": true, "id": "S"]
        }
        async let first: String? = Task.detached { c.run(k, work)["id"] as? String }.value
        try? await Task.sleep(nanoseconds: 100_000_000)
        async let second: String? = Task.detached { c.run(k, work)["id"] as? String }.value
        try? await Task.sleep(nanoseconds: 100_000_000)
        gate.signal()
        let (a, b) = await (first, second)
        #expect(a == "S" && b == "S")
        #expect(counter.withLock { $0 } == 1)
    }

    @Test("a start that can't wait: the second claim within 10 s is dropped")
    func claim() {
        let c = SessionStartCoalescer()
        let now = Date()
        #expect(c.claim(key(), now: now))
        #expect(!c.claim(key(), now: now + 2))
        c.finish(key(), ok: false)            // it failed: a retry may go
        #expect(c.claim(key(), now: now + 3))
        c.finish(key(), ok: true)
        #expect(!c.claim(key(), now: now + 5))
    }
}
