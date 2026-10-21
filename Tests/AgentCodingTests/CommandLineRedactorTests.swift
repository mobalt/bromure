import Foundation
import Testing
@testable import bromure_ac

/// Finding (CWE-532): "net.flow uploads process argv and tool commands with
/// no secret redaction". A flow's argv (per process) and its tool command,
/// and tool.use / command.run commands, went to the local timeline and the
/// org event stream as typed — `curl -u user:password`, bearer headers,
/// pasted tokens included.
@Suite("Command lines lose their secrets before they're recorded or uploaded")
struct CommandLineRedactorTests {
    @Test("passwords, header values, secret flags, URL userinfo and known tokens are taken out")
    func redact() {
        let r = CommandLineRedactor.redact
        #expect(r("curl -u alice:hunter2 https://x.example") == "curl -u alice:*** https://x.example")
        #expect(r("curl -ualice:hunter2 https://x.example") == "curl -ualice:*** https://x.example")
        #expect(r("mkdir -p a:b && ssh -p 22 host") == "mkdir -p a:b && ssh -p 22 host")
        #expect(r(#"curl -H "Authorization: Bearer abc.def.ghi" https://api.example"#)
                == #"curl -H "Authorization: Bearer ***" https://api.example"#)
        #expect(r("curl -H 'X-Api-Key: k123' x") == "curl -H 'X-Api-Key: ***' x")
        #expect(r("git clone https://bob:s3cret@github.com/acme/app") == "git clone https://bob:***@github.com/acme/app")
        #expect(r("mysql --password hunter2 db") == "mysql --password *** db")
        #expect(r("deploy --token=abc123 now") == "deploy --token=*** now")
        #expect(r("API_KEY=abc123 DB_PASSWORD=pw ./run") == "API_KEY=*** DB_PASSWORD=*** ./run")
        #expect(r("curl 'https://x.example/cb?access_token=zzz&id=1'") == "curl 'https://x.example/cb?access_token=***&id=1'")
        let gh = r("gh auth login --with-token ghp_" + String(repeating: "a", count: 36))
        #expect(!gh.contains("ghp_aaaa") && gh.contains("[GitHub token #"))
        // Nothing secret: left alone.
        #expect(r("curl -sS https://pypi.org/simple/requests/") == "curl -sS https://pypi.org/simple/requests/")
        #expect(r("git log --author=bob -n 5") == "git log --author=bob -n 5")
    }

    /// Finding (CWE-532): "Cookie flags and secrets past the first space are
    /// still stored and uploaded" — every value stopped at the first space or
    /// quote, and curl's own cookie flags weren't recognized.
    @Test("cookies (header, -b, --cookie) and quoted secrets with spaces are taken out whole")
    func valuesPastTheFirstSpace() {
        let r = CommandLineRedactor.redact
        #expect(r("curl -H 'Cookie: session=SECRET; csrf=OTHER' https://x.example")
                == "curl -H 'Cookie: ***' https://x.example")
        #expect(r(#"curl -H "Authorization: Bearer abc def" x"#) == #"curl -H "Authorization: Bearer ***" x"#)
        #expect(r("curl --cookie 'session=SECRET; csrf=OTHER' x") == "curl --cookie '***' x")
        #expect(r("curl -b 'session=SECRET' x") == "curl -b '***' x")
        #expect(r("curl -b session=SECRET x") == "curl -b *** x")
        #expect(r("curl --cookie=session=SECRET x") == "curl --cookie=*** x")
        #expect(r(#"curl -u "alice:my hunter2" x"#) == #"curl -u "alice:***" x"#)
        #expect(r(#"tool --password="my hunter2" go"#) == #"tool --password="***" go"#)
        #expect(r("tool --token 'a b c' go") == "tool --token '***' go")
        #expect(r(#"API_KEY="hunter2 extra" ./run"#) == #"API_KEY="***" ./run"#)
        #expect(r(#"curl -d '{"password": "a b", "user": "bob"}' x"#) == #"curl -d '{"password": "***", "user": "bob"}' x"#)
        // The sentry's argv: arguments joined by spaces, quotes gone.
        #expect(r("curl -H Cookie: session=SECRET; csrf=OTHER https://x.example")
                == "curl -H Cookie: *** https://x.example")
        #expect(r("curl --cookie session=SECRET; csrf=OTHER https://x.example") == "curl --cookie *** https://x.example")
        // Not cookies: a cookie file, a cookie jar, a git branch.
        #expect(r("curl -b cookies.txt -c jar.txt x") == "curl -b cookies.txt -c jar.txt x")
        #expect(r("curl --cookie-jar /tmp/jar x") == "curl --cookie-jar /tmp/jar x")
        #expect(r("git checkout -b fix-login && git push") == "git checkout -b fix-login && git push")
        // Several in one line, each whole.
        #expect(r(#"curl -u "a:b c" -H 'Cookie: s=1; t=2' --password 'p q'"#)
                == #"curl -u "a:***" -H 'Cookie: ***' --password '***'"#)
    }

    @Test("a net.flow's argv per process and its tool command are scrubbed; other fields aren't touched")
    func scrubFlow() {
        let data: [String: AnyJSON] = [
            "dst": .string("1.2.3.4"), "host": .string("api.example"),
            "processes": .array([
                .object(["comm": .string("bash"), "argv": .string("bash -c 'curl -u u:pw https://api.example'")]),
                .object(["comm": .string("curl"), "argv": .string("curl -u u:pw https://api.example")]),
            ]),
            "agent": .object(["tool": .string("Bash"), "command": .string("curl -u u:pw https://api.example")]),
            "reason": .string("token=keep-me-this-is-not-a-command-field"),
        ]
        let out = CommandLineRedactor.scrub(data)
        guard case .array(let procs)? = out["processes"] else { Issue.record("no processes"); return }
        for p in procs {
            guard case .object(let o) = p, case .string(let a)? = o["argv"] else { Issue.record("no argv"); continue }
            #expect(!a.contains("u:pw") && a.contains("u:***"))
        }
        guard case .object(let agent)? = out["agent"], case .string(let c)? = agent["command"] else { Issue.record("no command"); return }
        #expect(c == "curl -u u:*** https://api.example")
        if case .string(let host)? = out["host"] { #expect(host == "api.example") }
        if case .string(let reason)? = out["reason"] { #expect(reason.contains("keep-me")) }
    }

    @Test("the emitter scrubs before the timeline records a net.flow (row text and its stored detail)")
    @MainActor func emitterScrubs() async throws {
        let pid = UUID()
        await BACEventEmitter.shared.emit(profileID: pid, eventType: "net.flow", eventData: [
            "proto": .string("tcp"), "dst": .string("10.0.0.5"), "dport": .int(5432), "decision": .string("allow"),
            "processes": .array([.object(["pid": .int(7), "comm": .string("psql"),
                                          "argv": .string("psql postgres://app:pw1@db/x")])]),
            "agent": .object(["tool": .string("Bash"), "tool_use_id": .string("t1"),
                              "command": .string("PGPASSWORD=pw1 psql -h db")]),
            "command": .string("PGPASSWORD=pw1 psql -h db"),
        ])
        let row = try #require(SecurityTimeline.shared.allEvents.last { $0.profileID == pid })
        #expect(!row.condition.contains("pw1"))
        let stored = String(decoding: try JSONEncoder().encode(row.detail ?? [:]), as: UTF8.self)
        #expect(!stored.isEmpty && !stored.contains("pw1"))
        #expect(stored.contains("app:***@db"))
    }
}
