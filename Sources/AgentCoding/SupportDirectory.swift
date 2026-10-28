import Foundation

/// The app's data folder — profiles, VM disks, settings, secrets, traces —
/// and where it lives.
///
/// `name` is the folder under ~/Library/Application Support (and under
/// ~/Library/Logs): "BromureAC", unless the bundle's Info.plist names another
/// with `BromureSupportDirName`. `url` is that folder; every data path in
/// Sources/AgentCoding hangs off it instead of rebuilding
/// `applicationSupportDirectory/<name>` on the spot, and `logsURL` is the
/// log folder.
///
/// A build signed by a different team gets a different Data Protection
/// Keychain master key (`SecretsVault`), so it can't decrypt anything the
/// release build encrypted — its logins, workspace secrets and model keys —
/// and the release can't read what it writes. Giving such a build its own
/// folder keeps the two from locking each other out. The `bromure-ac` CLI
/// inside the bundle reads the same Info.plist, so it reaches the same
/// instance's control socket.
///
/// Bromure Sidecar shares this file (Sources/AgentHost/Shared) to find the
/// Bromure AC on this Mac it attaches to. Its own folder stays
/// BromureSidecar, so it reads a key that says whose folder this is:
/// `BromureACSupportDirName`.
enum ACSupportDir {
    static let defaultName = "BromureAC"

    #if AGENT_HOST
    static let infoPlistKey = "BromureACSupportDirName"
    #else
    static let infoPlistKey = "BromureSupportDirName"
    #endif

    static let name: String = resolve(
        Bundle.main.object(forInfoDictionaryKey: infoPlistKey) as? String)

    /// A symlink to the binary outside its bundle (`~/.local/bin/bromure-ac`,
    /// `/usr/local/bin/bromure-cli`) has no Info.plist around it: `Bundle.main`
    /// is found by walking up from the executable path *as invoked*, so this
    /// folder's name, the bundle identifier the settings live under and the
    /// build name would all read as missing, and the CLI would talk to the
    /// wrong data. Run the real binary instead, with the same arguments
    /// (argv[0] included, so `bromure-cli` stays `bromure-cli`) and
    /// environment. A symlinked *directory* on the way (`…-builds/stable/`)
    /// is fine: the bundle is still around the executable. First thing in
    /// `main()`; a no-op for the app itself.
    static func reexecIfInvokedThroughSymlink() {
        var size: UInt32 = 0
        _ = _NSGetExecutablePath(nil, &size)
        var buf = [CChar](repeating: 0, count: Int(size) + 1)
        guard _NSGetExecutablePath(&buf, &size) == 0 else { return }
        let invoked = String(cString: buf)
        let real = URL(fileURLWithPath: invoked).resolvingSymlinksInPath().path
        guard real != invoked, Bundle.main.bundleURL.pathExtension != "app",
              FileManager.default.isExecutableFile(atPath: real) else { return }
        var argv: [UnsafeMutablePointer<CChar>?] = CommandLine.arguments.map { strdup($0) }
        argv.append(nil)
        execv(real, &argv)   // returns only on failure: carry on as invoked
    }

    /// A single path component, or the default: never a path that escapes
    /// Application Support.
    static func resolve(_ configured: String?) -> String {
        guard let s = configured?.trimmingCharacters(in: .whitespacesAndNewlines),
              !s.isEmpty, s != ".", s != "..", !s.contains("/"), !s.contains(":")
        else { return defaultName }
        return s
    }

    #if !AGENT_HOST
    /// `~/Library/Application Support/<name>/`: the data folder. Every data
    /// path hangs off it.
    static var url: URL {
        applicationSupportDirectory.appendingPathComponent(name, isDirectory: true)
    }
    /// `~/Library/Logs/<name>/`.
    static var logsURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Logs/\(name)", isDirectory: true)
    }

    static var applicationSupportDirectory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
    }
    #endif
}
