import Testing
@testable import bromure_ac

@Suite("Support directory name")
struct SupportDirectoryTests {
    @Test("No Info.plist key means the release folder")
    func defaultName() {
        #expect(ACSupportDir.resolve(nil) == "BromureAC")
        // The test runner's bundle has no BromureSupportDirName.
        #expect(ACSupportDir.name == "BromureAC")
    }

    @Test("bromure-ac reads its own folder's key (the Sidecar reads BromureACSupportDirName)")
    func infoPlistKey() {
        #expect(ACSupportDir.infoPlistKey == "BromureSupportDirName")
    }

    @Test("A configured name is used, trimmed")
    func configured() {
        #expect(ACSupportDir.resolve("BromureACDev") == "BromureACDev")
        #expect(ACSupportDir.resolve("  BromureACDev\n") == "BromureACDev")
    }

    @Test("A name that isn't one path component falls back to the release folder")
    func rejected() {
        for bad in ["", "   ", ".", "..", "../Elsewhere", "a/b", "/tmp", "a:b"] {
            #expect(ACSupportDir.resolve(bad) == "BromureAC", "\(bad)")
        }
    }
}
