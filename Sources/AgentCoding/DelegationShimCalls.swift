import Foundation

/// The calls a Sidecar agent's delegation MCP shim (`__mcp-delegation`) has
/// in flight, by JSON-RPC id — what it sends again when its stream was the
/// hub's local fallback (nothing done), and answers with an error when a
/// relay stream drops or falls silent (maybe done). Shared with Bromure AC's
/// tests (the Sidecar target has none).
struct DelegationShimCalls {
    struct Call {
        var id: Any
        var key: String
        var line: Data
        var gen: Int
        var sentAt: Date
        var limit: TimeInterval
        var label: String
    }
    private(set) var calls: [Call] = []

    /// How long a call may go unanswered on a relay: a blocking tool
    /// (`wait`, `ask`, `request`: up to 50 s on the server) gets its own
    /// timeout plus a margin; anything else a generous bound.
    static func limit(method: String, params: [String: Any]?) -> TimeInterval {
        guard method == "tools/call" else { return 60 }
        let name = params?["name"] as? String ?? ""
        let args = params?["arguments"] as? [String: Any]
        if ["wait", "ask", "request"].contains(name) {
            let t = (args?["timeout_seconds"] as? Double) ?? Double(args?["timeout_seconds"] as? Int ?? 50)
            return min(max(t, 0), 50) + 40
        }
        return 300
    }

    static func key(_ id: Any) -> String {
        (try? JSONSerialization.data(withJSONObject: ["k": id])).map { String(decoding: $0, as: UTF8.self) } ?? "\(id)"
    }

    /// A request line (one with a method and an id) is in flight from now.
    mutating func sent(_ line: Data, on gen: Int, now: Date = Date()) {
        guard let msg = (try? JSONSerialization.jsonObject(with: line)) as? [String: Any],
              let method = msg["method"] as? String, let id = msg["id"] else { return }
        let k = Self.key(id)
        calls.removeAll { $0.key == k }
        let params = msg["params"] as? [String: Any]
        let name = params?["name"] as? String
        calls.append(Call(id: id, key: k, line: line, gen: gen, sentAt: now,
                          limit: Self.limit(method: method, params: params),
                          label: name.map { "\(method) \($0)" } ?? method))
    }

    /// A reply line (an id, no method) settles its call.
    mutating func answered(_ line: Data) {
        guard let msg = (try? JSONSerialization.jsonObject(with: line)) as? [String: Any],
              msg["method"] == nil, let id = msg["id"] else { return }
        let k = Self.key(id)
        calls.removeAll { $0.key == k }
    }

    /// The calls that went out on `gen`, removed.
    mutating func take(gen: Int) -> [Call] {
        let mine = calls.filter { $0.gen == gen }
        calls.removeAll { $0.gen == gen }
        return mine
    }

    func overdue(now: Date) -> [Call] {
        calls.filter { now.timeIntervalSince($0.sentAt) > $0.limit }
    }

    static let lostText = "The link to Bromure AC dropped while this call was under way, so it may or may not have been done. Before retrying, check: list_delegations shows each one's state and last message — a reply taken by the lost call is there, not in read_inbox."

    /// What Claude gets for a call lost with its stream.
    static func lostReply(_ c: Call) -> Data {
        var reply: [String: Any] = ["jsonrpc": "2.0", "id": c.id]
        if c.label.hasPrefix("tools/call") {
            reply["result"] = ["content": [["type": "text", "text": lostText]], "isError": true]
        } else {
            reply["error"] = ["code": -32000, "message": lostText]
        }
        let data = (try? JSONSerialization.data(withJSONObject: reply)) ?? Data()
        return data + Data([0x0A])
    }
}
