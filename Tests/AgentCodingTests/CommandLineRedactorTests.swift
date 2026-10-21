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
        // -u closing a cluster of short flags, its argument next or glued.
        #expect(r("curl -su alice:hunter2 https://x") == "curl -su alice:*** https://x")
        #expect(r("curl -fsSLu alice:hunter2 https://x") == "curl -fsSLu alice:*** https://x")
        #expect(r("curl -sLuuser:hunter2 https://x") == "curl -sLuuser:*** https://x")
        #expect(r("curl -kU proxy:pw -x http://p:3128 https://x") == "curl -kU proxy:*** -x http://p:3128 https://x")
        #expect(r("curl -4u alice:pw https://x") == "curl -4u alice:*** https://x")
        #expect(r("curl -6fsSLu alice:pw https://x") == "curl -6fsSLu alice:*** https://x")
        #expect(r("curl -0u alice:pw https://x") == "curl -0u alice:*** https://x")
        #expect(r("curl -#u alice:pw https://x") == "curl -#u alice:*** https://x")
        // A cluster without -u, or -u not last, is something else.
        #expect(r("curl -fsSL https://x/a:b") == "curl -fsSL https://x/a:b")
        #expect(r("tar -uvf a.tar b:c") == "tar -uvf a.tar b:c")
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

    /// Finding (CWE-670): "Command redaction erases rsync paths, PWD, and
    /// token: URLs that are not secrets".
    @Test("remote paths, the working directory and token-named URLs aren't secrets; real ones still go")
    func notSecrets() {
        let r = CommandLineRedactor.redact
        for kept in ["rsync -u host:/var/data dest", "rsync -u backup:~/data .",
                     "rsync -u host:src/file dest", "rsync -u user@host::module/file dest",
                     "rsync -u 'host:src/file' dest", "curl -s https://x; rsync -u host:src dest",
                     "PWD=/Users/someone/proj make -j", "OLDPWD=/tmp cd -",
                     "curl https://api.example/v1/tokens:list", "grep -r passwordless docs/",
                     "git push -u origin HEAD:main"] {
            #expect(r(kept) == kept, "\(kept)")
        }
        #expect(r("DB_PWD=hunter2 ./run") == "DB_PWD=*** ./run")
        #expect(r("API_TOKEN=abc API_TOKEN_V2=def ./run") == "API_TOKEN=*** API_TOKEN_V2=*** ./run")
        #expect(r("accessToken=abc client_secret=def") == "accessToken=*** client_secret=***")
        #expect(r(#"curl -d '{"token": "x"}' 'https://x/cb?access_token=zzz&id=1'"#)
                == #"curl -d '{"token": "***"}' 'https://x/cb?access_token=***&id=1'"#)
        #expect(r("curl -u alice:hunter2 https://x") == "curl -u alice:*** https://x")
        // A curl password is masked whatever it starts with, wrapped or not.
        #expect(r("curl -u alice:/s3cret https://x") == "curl -u alice:*** https://x")
        #expect(r("/usr/bin/curl -U bob:~hunter -x p https://x") == "/usr/bin/curl -U bob:*** -x p https://x")
        #expect(r("bash -c 'curl -sS -u alice:/BAiM0RVZnc= https://x'") == "bash -c 'curl -sS -u alice:*** https://x'")
        #expect(r("wget --user=bob:pw https://x") == "wget --user=bob:*** https://x")
        // The curl command reaches past quoted or escaped separators and
        // redirects; only a real command boundary ends it.
        for (cmd, out) in [
            ("curl 'https://x?a=1&b=2' -u alice:/s3cret", "curl 'https://x?a=1&b=2' -u alice:***"),
            (#"curl https://x?a=1\&b=2 -u alice:/s3cret"#, #"curl https://x?a=1\&b=2 -u alice:***"#),
            ("curl https://x?a=1&b=2 -u alice:/s3cret", "curl https://x?a=1&b=2 -u alice:***"),   // space-joined argv
            ("curl -d 'a;b' -u alice:/s3cret https://x", "curl -d 'a;b' -u alice:*** https://x"),
            ("curl -s https://x 2>&1 -u alice:/s3cret", "curl -s https://x 2>&1 -u alice:***"),
            ("curl &>/tmp/out -u alice:/s3cret https://x", "curl &>/tmp/out -u alice:*** https://x"),
            ("curl -s \\\n  -u alice:/s3cret https://x", "curl -s \\\n  -u alice:*** https://x"),
            ("curl -u alice:a 'https://x?a=1&b=2' -u bob:/second", "curl -u alice:*** 'https://x?a=1&b=2' -u bob:***"),
            ("CURL -u alice:/s3cret", "CURL -u alice:***"),
            // A substitution or a parenthesis in a URL nests; after it, the curl command resumes.
            ("curl https://en.wikipedia.org/wiki/Foo_(bar) -u alice:/s3cret", "curl https://en.wikipedia.org/wiki/Foo_(bar) -u alice:***"),
            ("curl -o $(mktemp) -u alice:/s3cret https://x", "curl -o $(mktemp) -u alice:*** https://x"),
            ("curl `date` -u alice:/s3cret https://x", "curl `date` -u alice:*** https://x"),
            ("curl <(echo x) -u alice:/s3cret", "curl <(echo x) -u alice:***"),
            ("curl -o >(tee /tmp/x) -u alice:/s3cret https://x", "curl -o >(tee /tmp/x) -u alice:*** https://x"),
            ("curl >| /tmp/out -u alice:/s3cret", "curl >| /tmp/out -u alice:***"),
            ("echo $(rsync -u host:src/file x) done", "echo $(rsync -u host:src/file x) done"),
            ("curl $(rsync -u host:src/file x)", "curl $(rsync -u host:src/file x)"),
            ("curl -u alice:secret && rsync -u host:src/file", "curl -u alice:*** && rsync -u host:src/file"),
        ] {
            #expect(r(cmd) == out, "\(cmd)")
        }
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
