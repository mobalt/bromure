import Foundation
import Testing

/// Issue #51: switching between terminal windows scrolled a scrolled-back
/// terminal to the bottom. Each switch moves size authority between tmux
/// clients of different sizes, so the window resizes; on a resize tmux keeps
/// the copy cursor's line and puts it on row 0, and the wheel left that
/// cursor on the bottom row — every switch dropped the view a whole screen.
/// The wheel bindings now park the cursor on the view's top line. This runs
/// bromure-agentd's own `create_session` bindings on a real tmux, feeds the
/// host's wheel sequences through an attached client, and resizes the way
/// window switches do.
@Suite("Terminal: a scrolled-back view survives window switches")
struct TerminalScrollResizeTests {
    private static let root = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()

    private static var tmux: String? {
        [root.appendingPathComponent("vendor/tmux/bin/tmux").path,
         "/opt/homebrew/bin/tmux", "/usr/local/bin/tmux", "/usr/bin/tmux"]
            .first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    private static var runnable: Bool {
        tmux != nil && FileManager.default.isExecutableFile(atPath: "/usr/bin/python3")
    }

    private static let driver = #"""
        import importlib.util, json, os, pty, select, struct, subprocess, sys, tempfile, time
        import fcntl, termios
        agentd, tmux = sys.argv[1], sys.argv[2]
        d = tempfile.mkdtemp()
        sock = os.path.join(d, "s")
        with open(os.path.join(d, "tmux"), "w") as f:
            f.write('#!/bin/sh\nexec "%s" -S "%s" -f /dev/null "$@"\n' % (tmux, sock))
        os.chmod(os.path.join(d, "tmux"), 0o755)
        os.environ["PATH"] = d + ":" + os.environ["PATH"]
        spec = importlib.util.spec_from_file_location("agentd", agentd)
        m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
        def tm(*a): return subprocess.run(["tmux", *a], capture_output=True, text=True).stdout.strip()
        out = {}
        try:
            m.HOME = d
            m.create_session()
            tm("respawn-pane", "-k", "-t", "bromure:0", "sh -c 'seq 1 2000; exec sleep 1000'")
            pid, fd = pty.fork()
            if pid == 0:
                os.environ["TERM"] = "xterm-256color"
                os.execvp("tmux", ["tmux", "attach", "-t", "bromure"])
            fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 100, 0, 0))
            def pump(t):
                end = time.time() + t
                while time.time() < end:
                    if select.select([fd], [], [], 0.05)[0]:
                        try: os.read(fd, 65536)
                        except OSError: return
            def wheel(seq, n):
                for _ in range(n):
                    os.write(fd, seq); pump(0.02)
                pump(0.3)
            def top():
                return int(tm("display", "-p", "-t", "bromure:0",
                              "#{e|-:#{history_size},#{scroll_position}}"))
            def mode(): return tm("display", "-p", "-t", "bromure:0", "#{pane_in_mode}")
            pump(0.8)
            tm("set-option", "-g", "window-size", "manual")
            wheel(b"\x1b[1000001~", 30)
            out["scrolled"] = mode() == "1"
            out["before"] = top()
            for x, y in [(120, 40), (100, 30), (80, 24), (100, 30)] * 3:
                tm("resize-window", "-t", "bromure:0", "-x", str(x), "-y", str(y))
            out["after"] = top()
            wheel(b"\x1b[1000002~", 5)
            out["down5"] = top()
            wheel(b"\x1b[1000002~", 100)
            out["leftAtBottom"] = mode() == "0"
        finally:
            subprocess.run(["tmux", "kill-server"], capture_output=True)
        print(json.dumps(out))
        """#

    @Test("the top line stays put across resizes; the wheel still scrolls and leaves at the bottom",
          .enabled(if: TerminalScrollResizeTests.runnable))
    func scrollPositionKept() throws {
        let agentd = Self.root.appendingPathComponent("Sources/AgentCoding/Resources/vm-setup/bromure-agentd.py")
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        proc.arguments = ["-I", "-c", Self.driver, agentd.path, try #require(Self.tmux)]
        let out = Pipe()
        proc.standardOutput = out
        proc.standardError = FileHandle.nullDevice
        try proc.run()
        proc.waitUntilExit()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        let r = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(r["scrolled"] as? Bool == true)
        let before = try #require(r["before"] as? Int)
        #expect(r["after"] as? Int == before, "view moved from line \(before) to \(r["after"] ?? "?")")
        #expect(r["down5"] as? Int == before + 5)
        #expect(r["leftAtBottom"] as? Bool == true)
    }
}
