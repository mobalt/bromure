import Foundation
import Testing

/// Finding (CWE-670): "Root apt install is reported failed while apt is
/// still running or has been SIGKILLed". Each apt step had its own 840 s
/// SIGKILL timeout (three steps against agentd's 900 s wait), so "failed"
/// reached the drawer while apt went on, and a kill mid-unpack left dpkg
/// interrupted. Now: one deadline, a SIGTERM stop of the whole group, a stop
/// when the caller goes away, and one install at a time.
@Suite("Sandbox: an approved apt install finishes or is stopped before it's reported", .serialized)
struct SandboxAptRunTests {
    private static let vmSetup = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("Sources/AgentCoding/Resources/vm-setup")
    private static var runnable: Bool { FileManager.default.isExecutableFile(atPath: "/usr/bin/python3") }

    /// sandboxd with a fake `apt-get` first on PATH. The fake logs each call
    /// (and a SIGTERM) to `log`; `update` sleeps UPDATE_SLEEP seconds.
    private func run(_ script: String) throws -> String {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("apt-run-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let fake = """
            #!/bin/sh
            log="$FAKE_LOG"
            trap 'echo TERM >> "$log"; exit 143' TERM
            echo "start $1" >> "$log"
            case "$1" in
              update) i=0; while [ $i -lt ${UPDATE_SLEEP:-0} ]; do sleep 1; i=$((i+1)); done
                      touch "$FAKE_DIR/lists"; echo "end update" >> "$log"; exit 0 ;;
              install) if [ ! -f "$FAKE_DIR/lists" ]; then echo "E: Unable to locate package curl"; echo "end install" >> "$log"; exit 100; fi
                       sleep ${INSTALL_SLEEP:-0}; echo "end install" >> "$log"; echo "installed"; exit 0 ;;
            esac
            """
        try fake.write(to: dir.appendingPathComponent("apt-get"), atomically: true, encoding: .utf8)
        chmod(dir.appendingPathComponent("apt-get").path, 0o755)
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        p.currentDirectoryURL = Self.vmSetup
        p.environment = ["PATH": dir.path + ":/usr/bin:/bin", "FAKE_DIR": dir.path,
                         "FAKE_LOG": dir.appendingPathComponent("log").path]
        p.arguments = ["-I", "-c", """
            import importlib.machinery, importlib.util, os, sys, threading, time, types
            os.uname = lambda: types.SimpleNamespace(sysname='Linux', nodename='t', release='6.8', version='', machine='aarch64')
            sys.path.insert(0, os.getcwd())
            ld = importlib.machinery.SourceFileLoader('sandboxd', 'bromure-sandboxd')
            m = importlib.util.module_from_spec(importlib.util.spec_from_loader('sandboxd', ld)); ld.exec_module(m)
            m.log = lambda *a: None
            D = os.environ['FAKE_DIR']; LOG = os.environ['FAKE_LOG']
            def calls(): return open(LOG).read().split() if os.path.exists(LOG) else []
            def reset():
                for f in (LOG, D + '/lists'):
                    if os.path.exists(f): os.remove(f)
            """ + "\n" + script]
        let pipe = Pipe(); p.standardOutput = pipe; p.standardError = pipe
        try p.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return String(decoding: data, as: UTF8.self)
    }

    @Test("Missing lists: install, update, install again, all within one call",
          .enabled(if: SandboxAptRunTests.runnable))
    func refreshThenInstall() throws {
        let out = try run("""
            code, text = m.apt_install(['curl'])
            print('OK', code == 0 and 'installed' in text and calls().count('start') == 3)
            """)
        #expect(out.contains("OK True"), Comment(rawValue: out))
    }

    @Test("Past the deadline, or with the caller gone, apt's group gets SIGTERM and the call reports it",
          .enabled(if: SandboxAptRunTests.runnable))
    func stopsGracefully() throws {
        let out = try run("""
            os.environ['UPDATE_SLEEP'] = '30'
            m.APT_DEADLINE_S = 2
            t = time.time(); code, text = m.apt_install(['curl'])
            print('DEADLINE', code != 0 and time.time() - t < 10 and 'TERM' in calls() and 'stopped' in text)
            reset(); m.APT_DEADLINE_S = 1800
            gone = time.time() + 1.5
            t = time.time(); code, text = m.apt_install(['curl'], cancelled=lambda: time.time() > gone)
            print('CANCELLED', code != 0 and time.time() - t < 10 and 'TERM' in calls() and 'abandoned' in text)
            """)
        #expect(out.contains("DEADLINE True"), Comment(rawValue: out))
        #expect(out.contains("CANCELLED True"), Comment(rawValue: out))
    }

    @Test("A second install waits for the one in flight instead of running beside it",
          .enabled(if: SandboxAptRunTests.runnable))
    func oneAtATime() throws {
        let out = try run("""
            open(D + '/lists', 'w').close()
            os.environ['INSTALL_SLEEP'] = '1'
            results = []
            ts = [threading.Thread(target=lambda: results.append(m.apt_install(['curl'])[0])) for _ in range(2)]
            for t in ts: t.start()
            for t in ts: t.join()
            c = calls()
            print('SERIAL', results == [0, 0] and c == ['start', 'install', 'end', 'install', 'start', 'install', 'end', 'install'])
            """)
        #expect(out.contains("SERIAL True"), Comment(rawValue: out))
    }

    @Test("The supervisor notices its caller hanging up", .enabled(if: SandboxAptRunTests.runnable))
    func peerGone() throws {
        let out = try run("""
            import socket
            a, b = socket.socketpair()
            print('ALIVE', not m._peer_gone(a))
            b.close()
            print('GONE', m._peer_gone(a))
            """)
        #expect(out.contains("ALIVE True") && out.contains("GONE True"), Comment(rawValue: out))
    }
}
