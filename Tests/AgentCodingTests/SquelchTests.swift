import Foundation
import AppKit
import SwiftUI
import Testing
@testable import bromure_ac

/// Squelch: command output noise is cut
/// out of the tool results an agent sends its model, the savings are
/// counted per workspace and conversation, and nothing else in the request
/// changes.
@Suite("Squelch: command output without the noise")
struct SquelchFilterTests {
    private func pytestOutput(passing: Int) -> String {
        var s = "============================= test session starts ==============================\n"
        s += "platform linux -- Python 3.12.3, pytest-8.3.2, pluggy-1.5.0\ncollected \(passing + 1) items\n\n"
        for i in 0..<passing { s += "tests/test_api.py::test_endpoint_\(i) PASSED                         [ \(i % 100)%]\n" }
        s += "tests/test_api.py::test_retry_budget FAILED                           [100%]\n\n"
        s += "=================================== FAILURES ===================================\n"
        s += "______________________________ test_retry_budget _______________________________\n\n"
        s += "    def test_retry_budget():\n>       assert budget.remaining == 3\nE       assert 2 == 3\n\n"
        s += "tests/test_api.py:88: AssertionError\n"
        s += "=========================== short test summary info ============================\n"
        s += "FAILED tests/test_api.py::test_retry_budget - assert 2 == 3\n"
        s += "========================= 1 failed, \(passing) passed in 4.12s =========================\n"
        return s
    }

    @Test("pytest: passing tests go, the failure and its traceback stay")
    func pytest() throws {
        let out = pytestOutput(passing: 120)
        let r = try #require(Squelch.trim(command: "cd api && python -m pytest -v tests/", output: out))
        #expect(r.family == .tests)
        #expect(!r.text.contains("test_endpoint_7 PASSED"))
        #expect(r.text.contains("test_retry_budget FAILED"))
        #expect(r.text.contains("E       assert 2 == 3"))
        #expect(r.text.contains("tests/test_api.py:88: AssertionError"))
        #expect(r.text.contains("1 failed, 120 passed"))
        #expect(r.dropped["passing tests"] == 120)
        #expect(r.text.contains(Squelch.fullOutputMarker))
        #expect(r.keptBytes * 4 < r.rawBytes)
        // The same input always gives the same text (the prompt cache).
        #expect(Squelch.trim(command: "cd api && python -m pytest -v tests/", output: out) == r)
    }

    @Test("what the agent reads as content is never touched")
    func verbatim() {
        let file = String(repeating: "    assert x == 1  # PASSED\n", count: 200)
        for cmd in ["cat tests/test_api.py", "sed -n 1,200p x.py", "git diff", "git show HEAD", "head -400 log.txt",
                    "git log -20", "jq . big.json"] {
            #expect(Squelch.trim(command: cmd, output: file) == nil, "\(cmd)")
        }
        // Small outputs and the escape hatch are passed through too.
        #expect(Squelch.trim(command: "pytest", output: "1 passed in 0.1s\n") == nil)
        #expect(Squelch.trim(command: "BROMURE_FULL_OUTPUT=1 pytest -v", output: pytestOutput(passing: 100)) == nil)
    }

    @Test("the command that does the work decides, through wrappers and chains")
    func classification() {
        #expect(Squelch.family(of: "cd web && CI=1 npx jest --ci 2>&1") == .tests)
        #expect(Squelch.family(of: "timeout 600 go test ./... -run TestX") == .tests)
        #expect(Squelch.family(of: "sudo -E apt-get install -y libssl-dev") == .install)
        #expect(Squelch.family(of: "npm ci && npm run build") == .build)
        #expect(Squelch.family(of: "pnpm run test:unit") == .tests)
        #expect(Squelch.family(of: "uv run pytest -q") == .tests)
        #expect(Squelch.family(of: "swift build -c release 2>&1") == .build)
        #expect(Squelch.family(of: "xcodebuild -scheme App test") == .tests)
        #expect(Squelch.family(of: "git push origin main") == .git)
        #expect(Squelch.family(of: "docker compose logs api") == .logs)
        #expect(Squelch.family(of: "rg -n 'func ' Sources") == .search)
        // A pipeline the agent shaped itself keeps what it chose.
        #expect(Squelch.family(of: "pytest -v | tail -40") == .other)
        #expect(Squelch.family(of: "cat a.txt | wc -l") == .verbatim)
        // Separators inside quotes don't split the command.
        #expect(Squelch.family(of: "echo 'a && b' ; pytest") == .tests)
        #expect(Squelch.family(of: "python -c 'import x; print(x)'") == .verbatim)
    }

    @Test("installs: download chatter and deprecation notices go, errors stay")
    func installs() throws {
        var npm = ""
        for i in 0..<40 { npm += "npm warn deprecated inflight@1.0.\(i): This module is not supported, and leaks memory.\n" }
        npm += "npm error code ERESOLVE\nnpm error ERESOLVE unable to resolve dependency tree\n"
        npm += "\nadded 1312 packages, and audited 1313 packages in 21s\n"
        let r = try #require(Squelch.trim(command: "npm install", output: npm))
        #expect(r.family == .install)
        #expect(!r.text.contains("inflight@1.0.3"))
        #expect(r.text.contains("npm error ERESOLVE unable to resolve dependency tree"))
        #expect(r.text.contains("added 1312 packages"))

        var pip = ""
        for i in 0..<30 {
            pip += "Collecting pkg\(i)==1.\(i)\n  Downloading pkg\(i)-1.\(i)-py3-none-any.whl (\(i * 10) kB)\n"
            pip += "     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ \(i * 10).0/\(i * 10).0 kB 3.1 MB/s eta 0:00:00\n"
        }
        pip += "ERROR: Could not find a version that satisfies the requirement nope==9\n"
        pip += "Successfully installed pkg0-1.0 pkg1-1.1\n"
        let p = try #require(Squelch.trim(command: "pip install -r requirements.txt", output: pip))
        #expect(!p.text.contains("Collecting pkg4=="))
        #expect(p.text.contains("ERROR: Could not find a version"))
        #expect(p.text.contains("Successfully installed"))
    }

    @Test("builds: per-file compile lines and xcodebuild steps go, diagnostics stay")
    func builds() throws {
        var cargo = ""
        for i in 0..<80 { cargo += "   Compiling crate\(i) v0.\(i).3\n" }
        cargo += "error[E0425]: cannot find value `foo` in this scope\n --> src/main.rs:4:5\n  |\n4 |     foo\n  |     ^^^ not found in this scope\n"
        cargo += "error: could not compile `app` (bin \"app\") due to 1 previous error\n"
        let c = try #require(Squelch.trim(command: "cargo build", output: cargo))
        #expect(!c.text.contains("Compiling crate12"))
        #expect(c.text.contains("error[E0425]"))
        #expect(c.text.contains(" --> src/main.rs:4:5"))
        #expect(c.text.contains("  |     ^^^ not found in this scope"))

        var xc = ""
        for i in 0..<30 {
            xc += "CompileSwift normal arm64 /src/App/File\(i).swift (in target 'App' from project 'App')\n"
            xc += "    cd /src/App\n    builtin-swiftTaskExecution -- /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/swift-frontend -frontend -c -primary-file /src/App/File\(i).swift\n\n"
        }
        xc += "/src/App/File3.swift:12:9: error: cannot find 'bar' in scope\n        bar()\n        ^~~\n"
        xc += "** BUILD FAILED **\n"
        let x = try #require(Squelch.trim(command: "xcodebuild -scheme App build", output: xc))
        #expect(!x.text.contains("builtin-swiftTaskExecution"))
        #expect(x.text.contains("File3.swift:12:9: error: cannot find 'bar' in scope"))
        #expect(x.text.contains("** BUILD FAILED **"))
    }

    @Test("git: transfer counters and hints go")
    func git() throws {
        var push = "Enumerating objects: 1203, done.\nCounting objects: 100% (1203/1203), done.\n"
        push += "Delta compression using up to 12 threads\nCompressing objects: 100% (640/640), done.\n"
        push += "Writing objects: 100% (1100/1100), 2.31 MiB | 4.20 MiB/s, done.\n"
        push += "Total 1100 (delta 702), reused 0 (delta 0), pack-reused 0\n"
        push += "remote: Resolving deltas: 100% (702/702), completed with 88 local objects.\n"
        push += "To github.com:example/app.git\n   1a2b3c4..5d6e7f8  main -> main\n"
        push += String(repeating: "remote: \n", count: 3)
        var t = Squelch.Trimmer(push, family: Squelch.family(of: "git push origin main"))
        t.run()
        #expect(t.lines.contains("   1a2b3c4..5d6e7f8  main -> main"))
        #expect(!t.lines.contains { $0.hasPrefix("Writing objects") || $0 == "remote: " })
        #expect(t.dropped["transfer progress"] == 8)
        // A push this short isn't worth a note: the agent gets it as it was.
        #expect(Squelch.trim(command: "git push origin main", output: push) == nil)
    }

    @Test("escapes and redrawn progress lines are cleaned")
    func cleaning() {
        let s = "\u{1B}[32mok\u{1B}[0m\nDownloading  10%\rDownloading  50%\rDownloading 100%\ndone\n"
        #expect(Squelch.cleaned(s) == "ok\nDownloading 100%\ndone\n")
    }

    @Test("logs: lines that differ only in their numbers collapse")
    func logs() throws {
        var log = ""
        for i in 0..<60 { log += "2026-10-19T12:00:\(String(format: "%02d", i)).123Z INFO health check ok latency=\(i)ms\n" }
        log += "2026-10-19T12:01:00.000Z ERROR upstream refused connection\n"
        let r = try #require(Squelch.trim(command: "docker logs api --tail 200", output: log))
        #expect(r.text.contains("59 more like the line above"))
        #expect(r.text.contains("ERROR upstream refused connection"))
    }
}

@Suite("Squelch: requests rewritten in place")
struct SquelchRewriterTests {
    private func noisy() -> String {
        (0..<150).map { "tests/test_x.py::test_\($0) PASSED" }.joined(separator: "\n") + "\n1 failed, 150 passed\nFAILED tests/test_x.py::test_z\n"
    }

    private func json(_ o: Any) -> Data { try! JSONSerialization.data(withJSONObject: o, options: [.sortedKeys]) }

    @Test("Anthropic: a Bash result is trimmed, a Read result and every other byte untouched")
    func anthropic() throws {
        let read = noisy()   // the same text, read from a file: never trimmed
        let body = json([
            "model": "claude-x", "metadata": ["user_id": #"{"device_id":"d","session_id":"6f1c2c1e-1111-4222-8333-444455556666"}"#],
            "messages": [
                ["role": "user", "content": "run the tests"],
                ["role": "assistant", "content": [
                    ["type": "thinking", "thinking": "hmm", "signature": "c2lnbmF0dXJl"],
                    ["type": "tool_use", "id": "toolu_1", "name": "Bash", "input": ["command": "pytest -v"]],
                    ["type": "tool_use", "id": "toolu_2", "name": "Read", "input": ["file_path": "/x.log"]],
                ]],
                ["role": "user", "content": [
                    ["type": "tool_result", "tool_use_id": "toolu_1", "content": noisy()],
                    ["type": "tool_result", "tool_use_id": "toolu_2", "content": [["type": "text", "text": read]]],
                ]],
            ],
        ])
        let o = SquelchRewriter.rewrite(body)
        #expect(o.trims.map(\.callID) == ["toolu_1"])
        #expect(o.seen.keys.sorted() == ["toolu_1"])
        let root = try #require(try JSONSerialization.jsonObject(with: o.body) as? [String: Any])
        let msgs = try #require(root["messages"] as? [[String: Any]])
        let results = try #require(msgs[2]["content"] as? [[String: Any]])
        let bash = try #require(results[0]["content"] as? String)
        #expect(!bash.contains("test_7 PASSED") && bash.contains("FAILED tests/test_x.py::test_z"))
        let readBack = try #require((results[1]["content"] as? [[String: Any]])?.first?["text"] as? String)
        #expect(readBack == read)
        // Byte-exact outside the one string: the prefix up to it is identical.
        let original = String(decoding: body, as: UTF8.self)
        let rewritten = String(decoding: o.body, as: UTF8.self)
        let start = try #require(original.range(of: #""content":"tests\/test_x.py::test_0 PASSED"#))
        let end = try #require(original.range(of: #","tool_use_id":"toolu_1""#))
        #expect(rewritten.hasPrefix(original[..<start.lowerBound]))
        #expect(rewritten.hasSuffix(original[end.lowerBound...]))
        #expect(SquelchRewriter.sessionKey(headers: "POST /v1/messages HTTP/1.1\r\n", body: body)
                == "6f1c2c1e-1111-4222-8333-444455556666")
    }

    @Test("OpenAI chat and Responses (Codex's wrapped outputs)")
    func openAI() throws {
        let chat = json(["model": "kimi", "messages": [
            ["role": "assistant", "tool_calls": [["id": "c1", "type": "function",
                                                  "function": ["name": "Shell", "arguments": #"{"command":"pytest -v"}"#]]]],
            ["role": "tool", "tool_call_id": "c1", "content": noisy()],
        ]])
        let c = SquelchRewriter.rewrite(chat)
        #expect(c.trims.count == 1)

        let header = "Chunk ID: 9f2a\nWall time: 3.2 seconds\nProcess exited with code 1\nOriginal token count: 2100\nOutput:\n"
        let shellJSON = String(decoding: json(["output": noisy(), "metadata": ["exit_code": 1, "duration_seconds": 3.2]]), as: UTF8.self)
        let responses = json(["model": "gpt-5", "prompt_cache_key": "0199aaaa-bbbb-7ccc-8ddd-eeeeffff0000", "input": [
            ["type": "function_call", "call_id": "call_a", "name": "exec_command", "arguments": #"{"cmd":"pytest -v"}"#],
            ["type": "function_call_output", "call_id": "call_a", "output": header + noisy()],
            ["type": "function_call", "call_id": "call_b", "name": "shell",
             "arguments": #"{"command":["bash","-lc","pytest -v"]}"#],
            ["type": "function_call_output", "call_id": "call_b", "output": shellJSON],
            // Their calls came in earlier turns: call_c's the model announced
            // (a shell call), call_d's nobody saw — it may be a `cat` of a log.
            ["type": "function_call_output", "call_id": "call_c", "output": "============ test session starts ============\n" + noisy()],
            ["type": "function_call_output", "call_id": "call_d", "output": "============ test session starts ============\n" + noisy()],
        ]])
        let r = SquelchRewriter.rewrite(responses, priorCall: { $0 == "call_c" ? ("exec_command", "pytest -v") : nil })
        #expect(r.trims.map(\.callID) == ["call_a", "call_b", "call_c"])
        #expect(r.seen["call_d"] == nil)
        let root = try #require(try JSONSerialization.jsonObject(with: r.body) as? [String: Any])
        let input = try #require(root["input"] as? [[String: Any]])
        let a = try #require(input[1]["output"] as? String)
        #expect(a.hasPrefix(header) && !a.contains("test_9 PASSED"))
        let b = try #require(input[3]["output"] as? String)
        let bj = try #require(try JSONSerialization.jsonObject(with: Data(b.utf8)) as? [String: Any])
        #expect((bj["output"] as? String)?.contains("FAILED tests/test_x.py::test_z") == true)
        #expect((bj["metadata"] as? [String: Any])?["exit_code"] as? Int == 1)
        #expect(SquelchRewriter.sessionKey(headers: "POST /responses HTTP/1.1\r\nsession_id: 0199AAAA-bbbb-7ccc-8ddd-eeeeffff0000\r\n",
                                           body: Data()) == "0199aaaa-bbbb-7ccc-8ddd-eeeeffff0000")
    }

    @Test("every agent's wire shape: Claude, Codex, Grok, omp, Kimi")
    func everyAgent() throws {
        let out = noisy()
        let bodies: [(String, [String: Any])] = [
            ("claude", ["model": "claude", "messages": [
                ["role": "assistant", "content": [["type": "tool_use", "id": "t", "name": "Bash", "input": ["command": "pytest -v"]]]],
                ["role": "user", "content": [["type": "tool_result", "tool_use_id": "t", "content": [["type": "text", "text": out]]]]],
            ]]),
            ("codex", ["model": "gpt-5", "input": [
                ["type": "function_call", "call_id": "t", "name": "shell", "arguments": #"{"command":["bash","-lc","pytest -v"]}"#],
                ["type": "function_call_output", "call_id": "t", "output": out],
            ]]),
            ("grok", ["model": "grok-code", "input": [
                ["type": "function_call", "call_id": "t", "name": "bash", "arguments": #"{"command":"pytest -v"}"#],
                ["type": "function_call_output", "call_id": "t", "output": [["type": "input_text", "text": out]]],
            ]]),
            ("omp", ["model": "bromure/glm", "messages": [
                ["role": "assistant", "content": "", "tool_calls": [["id": "t", "type": "function",
                                                                     "function": ["name": "bash", "arguments": #"{"command":"pytest -v"}"#]]]],
                ["role": "tool", "tool_call_id": "t", "content": out],
            ]]),
            ("kimi", ["model": "kimi-k2", "messages": [
                ["role": "assistant", "content": "", "tool_calls": [["id": "t", "type": "function",
                                                                     "function": ["name": "Shell", "arguments": #"{"command":"pytest -v"}"#]]]],
                ["role": "tool", "tool_call_id": "t", "content": [["type": "text", "text": out]]],
            ]]),
        ]
        for (agent, body) in bodies {
            let o = SquelchRewriter.rewrite(json(body))
            #expect(o.trims.count == 1, "\(agent): not trimmed")
            #expect(o.trims.first?.command == "pytest -v", "\(agent): command not read")
            let text = String(decoding: o.body, as: UTF8.self)
            #expect(!text.contains("test_7 PASSED") && text.contains("FAILED tests"), "\(agent)")
        }
    }

    @Test("a call announced in the model's reply is matched with its bare result later; others are left alone")
    func registry() throws {
        let reg = SquelchCallRegistry()
        let ws = UUID()
        let done: [String: Any] = ["type": "response.output_item.done", "output_index": 0,
                                   "item": ["type": "function_call", "call_id": "call_z", "name": "exec_command",
                                            "arguments": #"{"cmd":"go test ./... -v"}"#]]
        reg.learn(fromServerEvent: json(done), profileID: ws)
        let read: [String: Any] = ["type": "response.output_item.done",
                                   "item": ["type": "function_call", "call_id": "call_r", "name": "read_file",
                                            "arguments": #"{"path":"log.txt"}"#]]
        reg.learn(fromServerEvent: json(read), profileID: ws)
        #expect(reg.call(ws, "call_z")?.command == "go test ./... -v")
        #expect(reg.call(UUID(), "call_z") == nil)   // per workspace

        let goOut = (0..<80).map { "=== RUN   TestThing\($0)\n--- PASS: TestThing\($0) (0.00s)" }.joined(separator: "\n")
            + "\n--- FAIL: TestBroken (0.01s)\n    thing_test.go:12: want 3, got 2\nFAIL\n"
        let chained = json(["type": "response.create", "previous_response_id": "resp_1", "input": [
            ["type": "function_call_output", "call_id": "call_z", "output": goOut],
            ["type": "function_call_output", "call_id": "call_r", "output": goOut],
        ]])
        let o = SquelchRewriter.rewrite(chained, priorCall: { reg.call(ws, $0) })
        #expect(o.trims.map(\.callID) == ["call_z"])
        let input = try #require((try JSONSerialization.jsonObject(with: o.body) as? [String: Any])?["input"] as? [[String: Any]])
        let z = try #require(input[0]["output"] as? String)
        #expect(!z.contains("--- PASS: TestThing3") && z.contains("--- FAIL: TestBroken") && z.contains("want 3, got 2"))
        #expect(input[1]["output"] as? String == goOut)   // a read: untouched

        // Codex code mode: `exec` runs a script, not a command line — its
        // output (here, a script that cats a test log) is never trimmed.
        let script: [String: Any] = ["type": "response.output_item.done",
                                     "item": ["type": "custom_tool_call", "call_id": "call_js", "name": "exec",
                                              "input": #"const r = await tools.exec_command({cmd: "cat go-test.log"});"#]]
        reg.learn(fromServerEvent: json(script), profileID: ws)
        let codeMode = json(["type": "response.create", "previous_response_id": "resp_2", "input": [
            ["type": "custom_tool_call_output", "call_id": "call_js", "output": [["type": "input_text", "text": goOut]]],
        ]])
        let c = SquelchRewriter.rewrite(codeMode, priorCall: { reg.call(ws, $0) })
        #expect(c.trims.isEmpty && c.body == codeMode)
    }

    @Test("string paths are exact through nesting and escapes")
    func paths() throws {
        let b = Array(#"{"a":[1,{"k":"v\"x","n":[true,"s"]}],"b":"t","c":{}}"#.utf8)
        let refs = try #require(JSONPath.strings(b))
        #expect(refs.map(\.path) == [[.key("a"), .index(1), .key("k")], [.key("a"), .index(1), .key("n"), .index(1)], [.key("b")]])
        #expect(JSONStrings.decode(b, refs[0].range) == "v\"x")
    }
}

@Suite("Squelch: savings are counted once, where they happened")
struct SquelchLedgerTests {
    @Test("a result resent every turn counts once; conversations and days add up; the cloud report drains")
    func ledger() throws {
        let ledger = SquelchLedger(file: nil)
        let ws = UUID()
        var o = SquelchRewriter.Outcome(body: Data())
        o.seen = ["t1": 4000, "t2": 800]
        o.trims = [.init(callID: "t1", command: "cd x && pytest -v", family: .tests, rawBytes: 4000, keptBytes: 400)]
        ledger.record(o, profileID: ws, conversation: "conv-1")
        ledger.record(o, profileID: ws, conversation: "conv-1")   // the next turn resends both
        let w = try #require(ledger.workspace(ws))
        #expect(w.total == SquelchTally(outputs: 2, trimmed: 1, rawBytes: 4800, keptBytes: 1200))
        #expect(w.total.savedTokens == 900)
        #expect(ledger.conversation(ws, "CONV-1") == w.total)
        #expect(w.commands["pytest"]?.savedBytes == 3600)
        #expect(w.families["tests"]?.trimmed == 1)

        let report = ledger.pendingCloudReport()
        #expect(report.rows.count == 1 && report.rows[0].savedTokens == 900)
        let events = SquelchCloud.events(report)
        #expect(events.count == 1 && events[0].profileID == ws && events[0].eventType == "tokens.squelch")
        if case .int(let saved)? = events.first?.data["saved_tokens"] { #expect(saved == 900) } else { Issue.record("no saved_tokens") }
        ledger.markReported(report)
        #expect(ledger.pendingCloudReport().isEmpty)
        var o2 = SquelchRewriter.Outcome(body: Data())
        o2.seen = ["t3": 100]
        ledger.record(o2, profileID: ws, conversation: nil)
        #expect(ledger.pendingCloudReport().rows.first?.outputs == 1)
    }

    @Test("a ledger from before the digest keys doesn't count its outputs again")
    func plainKeysMigrate() throws {
        // Finding: "Squelch savings are counted twice after the ledger key
        // change" — the first ledgers saved "conversation|callID" itself.
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("squelch-\(UUID())")
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("ledger.json")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let ws = UUID()
        var old = SquelchLedger.Workspace()
        old.total = SquelchTally(outputs: 3, trimmed: 0, rawBytes: 30, keptBytes: 30)
        old.counted = ["019a0000-aaaa-7bbb-8ccc-dddddddddddd|c1", "|c2",
                       SquelchLedger.countedKey(conversation: "019a0000-aaaa-7bbb-8ccc-dddddddddddd", callID: "c3")]
        try JSONEncoder().encode(SquelchLedger.Snapshot(workspaces: [ws.uuidString: old])).write(to: file)

        let ledger = SquelchLedger(file: file)
        var o = SquelchRewriter.Outcome(body: Data())
        o.seen = ["c1": 10, "c3": 10]
        ledger.record(o, profileID: ws, conversation: "019a0000-aaaa-7bbb-8ccc-dddddddddddd")
        o.seen = ["c2": 10]
        ledger.record(o, profileID: ws, conversation: nil)
        #expect(ledger.workspace(ws)?.total.outputs == 3)
        #expect(ledger.workspace(ws)?.counted.count == 3)
    }

    @Test("command labels name the work")
    func labels() {
        #expect(SquelchLedger.commandLabel("cd app && npm run test -- --ci") == "npm run test")
        #expect(SquelchLedger.commandLabel("CI=1 git push origin main") == "git push")
        #expect(SquelchLedger.commandLabel("python3 -m pytest -q") == "python3 pytest")
        #expect(SquelchLedger.commandLabel("pytest -v | tail") == "pytest")
    }
}

@Suite("Squelch: the header popover", .serialized)
@MainActor
struct SquelchPopoverTests {
    @Test("shows the switch, the conversation's savings and the machine's")
    func popover() throws {
        _ = NSApplication.shared
        let day = SquelchLedger.dayKey(Date())
        let summary = SquelchSummary(
            total: SquelchTally(outputs: 212, trimmed: 64, rawBytes: 1_840_000, keptBytes: 620_000),
            commands: [.init(name: "pytest", tally: SquelchTally(outputs: 30, trimmed: 30, rawBytes: 900_000, keptBytes: 120_000)),
                       .init(name: "npm install", tally: SquelchTally(outputs: 4, trimmed: 4, rawBytes: 300_000, keptBytes: 40_000))],
            days: (0..<14).map { .init(name: "d\($0)", tally: SquelchTally(outputs: 1, trimmed: 1, rawBytes: 40_000 * ($0 % 5 + 1), keptBytes: 9_000)) }
                + [.init(name: day, tally: SquelchTally())])
        var toggled: [Bool] = []
        let view = SquelchPopover(machine: "Kimi", enabled: true,
                                  session: SquelchTally(outputs: 41, trimmed: 12, rawBytes: 130_000, keptBytes: 80_000),
                                  summary: summary, setEnabled: { toggled.append($0) })
        let host = NSHostingView(rootView: view)
        let size = host.fittingSize
        host.frame = NSRect(origin: .zero, size: size)
        host.layoutSubtreeIfNeeded()
        #expect(size.width == 380)
        #expect(size.height > 300 && size.height < 900, "popover \(size.height) tall")
        if let out = ProcessInfo.processInfo.environment["SQUELCH_SHOT"],
           let rep = host.bitmapImageRepForCachingDisplay(in: host.bounds) {
            host.cacheDisplay(in: host.bounds, to: rep)
            try rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: out))
        }
        #expect(toggled.isEmpty)
    }

    @Test("hung off the header's one-line meta row, its text still wraps")
    func wrapsUnderHeaderLineLimit() throws {
        _ = NSApplication.shared
        func height(_ v: some View) -> CGFloat { NSHostingView(rootView: v).fittingSize.height }
        let popover = SquelchPopover(machine: "omp + z.ai", enabled: false, session: nil, summary: nil, setEnabled: { _ in })
        let free = height(popover)
        let inHeader = NSHostingView(rootView: popover.lineLimit(1))
        inHeader.frame = NSRect(origin: .zero, size: inHeader.fittingSize)
        inHeader.layoutSubtreeIfNeeded()
        #expect(inHeader.fittingSize.height == free, "clipped: \(inHeader.fittingSize.height) vs \(free)")
        if let out = ProcessInfo.processInfo.environment["SQUELCH_SHOT_OFF"],
           let rep = inHeader.bitmapImageRepForCachingDisplay(in: inHeader.bounds) {
            inHeader.cacheDisplay(in: inHeader.bounds, to: rep)
            try rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: out))
        }
    }
}

@Suite("Squelch: cost per request")
struct SquelchCostTests {
    @Test("a long conversation is rewritten quickly, and faster the second time")
    func cost() throws {
        var messages: [Any] = []
        for i in 0..<300 {
            let out = (0..<120).map { "tests/test_\(i).py::test_case_\($0) PASSED          [ \($0 % 100)%]" }.joined(separator: "\n")
                + "\n" + (0..<40).map { "ordinary output line \($0) that stays" }.joined(separator: "\n")
            messages.append(["role": "assistant", "content": [["type": "tool_use", "id": "t\(i)", "name": "Bash",
                                                               "input": ["command": i % 2 == 0 ? "pytest -v" : "ls -la"]]]])
            messages.append(["role": "user", "content": [["type": "tool_result", "tool_use_id": "t\(i)", "content": out]]])
        }
        let body = try JSONSerialization.data(withJSONObject: ["model": "m", "messages": messages])
        let t0 = Date()
        let first = SquelchRewriter.rewrite(body)
        let t1 = Date()
        let second = SquelchRewriter.rewrite(body)
        let t2 = Date()
        #expect(first.body == second.body)
        #expect(first.trims.count == 150)
        print(String(format: "squelch cost: %d KB body, first %.0f ms, again %.0f ms",
                     body.count / 1024, t1.timeIntervalSince(t0) * 1000, t2.timeIntervalSince(t1) * 1000))
        #expect(t2.timeIntervalSince(t1) < 1.0)
    }
}
