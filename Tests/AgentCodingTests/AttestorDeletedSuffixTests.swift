import Foundation
import Testing

/// Finding (CWE-807): "Attestor strips a real ' (deleted)' filename into an
/// allowlisted binary path". `exe_identity` always cut a trailing " (deleted)"
/// off `/proc/<pid>/exe`, but a LIVE file named `curl (deleted)` reads the
/// same: the guest user could exec such a sibling of any allowlisted path it
/// can write and be attested -- and TOFU-pinned -- as that path. Only a raw
/// path that isn't the running image is the kernel's annotation.
@Suite("Attestor: only the kernel's ' (deleted)' is cut, never a real name")
struct AttestorDeletedSuffixTests {
    static let script = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent().appendingPathComponent("Sources/AgentCoding/Resources/vm-setup/bromure-attestd.py")

    /// Runs `body` with the attestor module loaded as `a`, in a temp dir `d`; returns stdout.
    static func python(_ body: String) throws -> String {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("attest-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        p.arguments = ["python3", "-I", "-c", """
            import importlib.util, os, sys
            spec = importlib.util.spec_from_file_location("attestd", sys.argv[1])
            a = importlib.util.module_from_spec(spec); spec.loader.exec_module(a)
            d = sys.argv[2]
            \(body)
            """, script.path, dir.path]
        let out = Pipe()
        p.standardOutput = out
        try p.run()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        #expect(p.terminationStatus == 0)
        return String(decoding: data, as: UTF8.self)
    }

    @Test("a live file named '<x> (deleted)' keeps its name; an unlinked image loses the annotation")
    func liveVersusUnlinked() throws {
        let out = try Self.python("""
            live = os.path.join(d, "curl (deleted)")
            open(live, "w").write("forged")
            real = os.path.join(d, "curl")
            open(real, "w").write("real")
            gone = os.path.join(d, "old")
            open(gone, "w").write("old"); gone_st = os.stat(gone); os.unlink(gone)
            print(a.reported_path(live, os.stat(live)))                     # live: kept
            print(a.reported_path(gone + " (deleted)", gone_st))            # unlinked: cut
            print(a.reported_path(live, os.stat(real)))                     # raw is another file: cut
            print(a.reported_path(real, os.stat(real)))                     # no suffix: as is
            nested = os.path.join(d, "x (deleted)")
            open(nested, "w").write("n"); n_st = os.stat(nested); os.unlink(nested)
            print(a.reported_path(nested + " (deleted)", n_st))             # unlinked real name: one cut
            """)
        let lines = out.split(separator: "\n").map(String.init)
        #expect(lines.count == 5)
        #expect(lines[0].hasSuffix("/curl (deleted)"))
        #expect(lines[1].hasSuffix("/old"))
        #expect(lines[2].hasSuffix("/curl"))
        #expect(lines[3].hasSuffix("/curl"))
        #expect(lines[4].hasSuffix("/x (deleted)"))
    }

    @Test("exe_identity decides from the open exe's own inode")
    func wiring() throws {
        let src = try String(contentsOf: Self.script, encoding: .utf8)
        let fn = try #require(src.range(of: "def exe_identity(pid):"))
        let read = try #require(src[fn.upperBound...].range(of: "raw = os.readlink(\"/proc/%d/exe\" % pid)"))
        let code = src[read.upperBound...].prefix(300)
        #expect(code.contains("path = reported_path(raw, st)"))
        #expect(!code.contains("[: -len(_DELETED)]"))
    }
}
