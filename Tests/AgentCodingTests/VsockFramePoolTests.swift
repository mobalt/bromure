import Foundation
import Testing
@testable import bromure_ac

/// 5.4.0 ran a server out of memory (7.5 GB peak, no leak reported): the
/// kernel sentry and attestor bridges read guest frames on a raw Thread for
/// the VM's lifetime, whose autorelease pool never drains, so every frame's
/// JSON objects stayed alive until the VM stopped. Each frame now drains its
/// own pool: what one frame autoreleased is gone before the next is read.
@Suite("vsock bridges drain each frame's autoreleased objects")
struct VsockFramePoolTests {
    private final class Sentinel: NSObject {}

    /// Writes `count` frames to one end of a socket pair (in `encode`'s
    /// framing), closes it, and returns the other end.
    private func feed(_ count: Int, _ encode: @escaping (Data) -> Data) -> Int32 {
        var sv: [Int32] = [0, 0]
        _ = socketpair(AF_UNIX, SOCK_STREAM, 0, &sv)
        let w = sv[1]
        Thread.detachNewThread {
            for i in 0..<count {
                let json = try! JSONSerialization.data(withJSONObject: ["type": "event", "seq": i])
                let bytes = [UInt8](encode(json))
                var off = 0
                while off < bytes.count {
                    let n = bytes[off...].withUnsafeBytes { write(w, $0.baseAddress!, $0.count) }
                    if n <= 0 { break }
                    off += n
                }
            }
            close(w)
        }
        return sv[0]
    }

    /// Runs `serve` the way the bridges do (a raw Thread under one outer
    /// pool); `handle` autoreleases a sentinel per frame. Returns how many
    /// frames were handled and how many found the previous one's sentinel
    /// still alive.
    private func run(_ count: Int, _ serve: @escaping (@escaping () -> Void) -> Void) async -> (handled: Int, held: Int) {
        await withCheckedContinuation { cont in
            Thread.detachNewThread {
                var handled = 0, held = 0
                weak var last: Sentinel?
                autoreleasepool {
                    serve {
                        if last != nil { held += 1 }
                        let s = Sentinel()
                        last = s
                        _ = Unmanaged.passRetained(s).autorelease()   // the pool holds the last reference
                        handled += 1
                    }
                }
                cont.resume(returning: (handled, held))
            }
        }
    }

    @Test("kernel sentry frames")
    func sentryFrames() async {
        let fd = feed(50) { json in
            let n = json.count
            return Data([UInt8(n >> 24 & 0xFF), UInt8(n >> 16 & 0xFF), UInt8(n >> 8 & 0xFF), UInt8(n & 0xFF)]) + json
        }
        let r = await run(50) { tick in SentryBridge.serveFrames(fd) { _ in tick() } }
        close(fd)
        #expect(r.handled == 50)
        #expect(r.held == 0)
    }

    @Test("attestor lines")
    func attestorLines() async {
        let fd = feed(50) { $0 + Data([0x0A]) }
        let r = await run(50) { tick in
            var reader = LineReader(fd: fd)
            AttestorBridge.serveLines(&reader) { _ in tick() }
        }
        close(fd)
        #expect(r.handled == 50)
        #expect(r.held == 0)
    }
}
