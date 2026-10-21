import Foundation
import Testing
@testable import bromure_ac
import SandboxEngine

@Suite("Container traffic exempt from the MiTM", .serialized)
struct ContainerTrafficTests {
    /// A minimal IPv4 header with a correct checksum.
    static func header(tos: UInt8) -> [UInt8] {
        var h: [UInt8] = [0x45, tos, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0, 0,
                          0xac, 0x1b, 0x66, 0x02, 0x01, 0x01, 0x01, 0x01]
        let c = checksum(h); h[10] = UInt8(c >> 8); h[11] = UInt8(c & 0xff)
        return h
    }
    static func checksum(_ h: [UInt8]) -> UInt16 {
        var sum: UInt32 = 0
        for i in stride(from: 0, to: h.count, by: 2) where i != 10 { sum += UInt32(h[i]) << 8 | UInt32(h[i + 1]) }
        while sum > 0xffff { sum = (sum & 0xffff) + (sum >> 16) }
        return ~UInt16(sum)
    }

    @Test("The mark is read, stripped (ECN kept) and the checksum stays valid; other DSCPs are untouched")
    func strip() {
        for ecn: UInt8 in [0, 1, 2, 3] {
            var h = Self.header(tos: VMNetSwitch.containerDSCP << 2 | ecn)
            let took = h.withUnsafeMutableBufferPointer { VMNetSwitch.takeContainerMark($0.baseAddress!, ip: 0) }
            #expect(took)
            #expect(h[1] == ecn)
            #expect(UInt16(h[10]) << 8 | UInt16(h[11]) == Self.checksum(h))
        }
        var voip = Self.header(tos: 46 << 2)          // EF, a legitimate DSCP
        let took = voip.withUnsafeMutableBufferPointer { VMNetSwitch.takeContainerMark($0.baseAddress!, ip: 0) }
        #expect(!took && voip[1] == 46 << 2)
    }

    @Test("The switch honours the mark only while the sentry stamps it and the workspace allows it")
    func gating() {
        let pid = UUID()
        let svc = KernelSentryService.shared
        let old = svc.containerDirectProvider
        defer { svc.containerDirectProvider = old; svc.noteContainerMark(profileID: pid, active: false) }
        svc.containerDirectProvider = { $0 == pid }
        #expect(!VMNetSwitch.shared.isContainerTrafficDirect(profileID: pid))   // no sentry yet
        svc.noteContainerMark(profileID: pid, active: true)
        #expect(VMNetSwitch.shared.isContainerTrafficDirect(profileID: pid))
        svc.noteContainerMark(profileID: pid, active: false)                    // sentry gone → fail closed
        #expect(!VMNetSwitch.shared.isContainerTrafficDirect(profileID: pid))
        svc.noteContainerMark(profileID: pid, active: true)
        svc.containerDirectProvider = { _ in false }                            // option turned off
        svc.refreshContainerDirect(profileID: pid)
        #expect(!VMNetSwitch.shared.isContainerTrafficDirect(profileID: pid))
    }

    @Test("A tc change after boot revokes the exemption until the next boot; reconnects don't re-arm it")
    func tcRevokes() {
        let pid = UUID()
        let svc = KernelSentryService.shared
        let old = svc.containerDirectProvider
        defer { svc.containerDirectProvider = old; svc.rearmContainerMark(profileID: pid)
                svc.noteContainerMark(profileID: pid, active: false) }
        svc.containerDirectProvider = { $0 == pid }
        svc.noteContainerMark(profileID: pid, active: true)
        #expect(VMNetSwitch.shared.isContainerTrafficDirect(profileID: pid))
        #expect(svc.revokeContainerMark(profileID: pid))            // first revocation alarms
        #expect(!svc.revokeContainerMark(profileID: pid))           // later ones don't re-alarm
        #expect(!VMNetSwitch.shared.isContainerTrafficDirect(profileID: pid))
        svc.noteContainerMark(profileID: pid, active: true)         // a reconnect in the same boot
        #expect(!VMNetSwitch.shared.isContainerTrafficDirect(profileID: pid))
        svc.rearmContainerMark(profileID: pid)                      // a new boot's hello
        svc.noteContainerMark(profileID: pid, active: true)
        #expect(VMNetSwitch.shared.isContainerTrafficDirect(profileID: pid))
    }

    /// Finding (CWE-693): "A boot-phase tc change is ignored, so a pedit rule
    /// keeps forging the container mark". A unit on the workspace disk that
    /// installs a pedit before the session starts kept the exemption armed.
    @Test("A tc change revokes the exemption in the boot phase too")
    func tcRevokesDuringBoot() {
        let pid = UUID()
        let svc = KernelSentryService.shared
        let old = svc.containerDirectProvider
        defer { svc.containerDirectProvider = old; svc.rearmContainerMark(profileID: pid)
                svc.noteContainerMark(profileID: pid, active: false) }
        svc.containerDirectProvider = { $0 == pid }
        svc.noteContainerMark(profileID: pid, active: true)
        #expect(VMNetSwitch.shared.isContainerTrafficDirect(profileID: pid))
        let bridge = SentryBridge(profileID: pid, requirement: .bestEffort, restoring: false)
        bridge.handle(["type": "event", "seq": 1, "kind": "tc_change", "phase": "boot",
                       "op": "filter", "tc_kind": "u32", "comm": "tc", "pid": 412])
        #expect(!VMNetSwitch.shared.isContainerTrafficDirect(profileID: pid))
        // The session starting doesn't bring it back; only the next boot does.
        bridge.handle(["type": "heartbeat", "seq": 2, "phase": "session"])
        svc.noteContainerMark(profileID: pid, active: true)
        #expect(!VMNetSwitch.shared.isContainerTrafficDirect(profileID: pid))
    }

    /// Finding (CWE-693): "Restoring a VM forgets a container-mark
    /// revocation while the tc rule is still installed". The revocation
    /// lived only in the host process; a restored VM keeps its kernel and
    /// the qdisc, and its reconnect turned the exemption back on.
    @Test("A restored VM's reconnect keeps the mark revoked; a fresh boot re-arms it")
    func revocationSurvivesRestore() {
        let k = KernelSentryTests()
        let pid = UUID()
        let svc = KernelSentryService.shared
        let old = svc.containerDirectProvider
        let pin = FileManager.default.temporaryDirectory.appendingPathComponent("sentry-\(UUID()).pin")
        defer { svc.containerDirectProvider = old; svc.rearmContainerMark(profileID: pid)
                svc.noteContainerMark(profileID: pid, active: false)
                try? FileManager.default.removeItem(at: pin) }
        svc.containerDirectProvider = { $0 == pid }
        let marked: [String: Any] = ["container_mark": Int(VMNetSwitch.containerDSCP),
                                     "probes": Array(KernelSentryService.tcProbeSymbols)]
        func hello(_ extra: [String: Any]) -> Data {
            k.frame(["type": "hello", "v": 1, "boot_id": "b", "kernel": "k", "module": "1"]
                .merging(marked) { $1 }.merging(extra) { $1 })
        }
        // The first boot: the mark is honoured, then tc changes.
        let first = SentryBridge(profileID: pid, requirement: .bestEffort, restoring: false, pinFile: pin)
        let (_, g0, tap) = k.connect(first, hello(["secret": KernelSentryTests.secret]))
        tap.waitFor { VMNetSwitch.shared.isContainerTrafficDirect(profileID: pid) }
        #expect(VMNetSwitch.shared.isContainerTrafficDirect(profileID: pid))
        first.handle(["type": "event", "seq": 1, "kind": "tc_change", "phase": "session",
                      "op": "qdisc", "tc_kind": "pedit", "comm": "tc", "pid": 77])
        #expect(!VMNetSwitch.shared.isContainerTrafficDirect(profileID: pid))
        close(g0); tap.waitFor { !first.snapshot().connected }
        // Host restart: a new process (nothing revoked in memory), the VM restored.
        svc.rearmContainerMark(profileID: pid)
        let restored = SentryBridge(profileID: pid, requirement: .bestEffort, restoring: true, pinFile: pin)
        let proof = SentryBridge.reconnectProof(secret: KernelSentryTests.secret, bootID: "b", conn: 1)
        let (_, g1, tap1) = k.connect(restored, hello(["conn": 1, "proof": proof]))
        tap1.waitFor { restored.snapshot().connected }
        #expect(restored.snapshot().connected && tap1.alarms().isEmpty)
        usleep(50_000)
        #expect(!VMNetSwitch.shared.isContainerTrafficDirect(profileID: pid))
        close(g1); tap1.waitFor { !restored.snapshot().connected }
        // A real reboot: a new boot's first hello trusts the mark again.
        let rebooted = SentryBridge(profileID: pid, requirement: .bestEffort, restoring: false, pinFile: pin)
        let (_, g2, tap2) = k.connect(rebooted, k.frame(["type": "hello", "v": 1, "boot_id": "b2", "kernel": "k",
                                                         "module": "1", "secret": String(repeating: "cd", count: 32)]
                                                        .merging(marked) { $1 }))
        tap2.waitFor { VMNetSwitch.shared.isContainerTrafficDirect(profileID: pid) }
        #expect(VMNetSwitch.shared.isContainerTrafficDirect(profileID: pid))
        close(g2)
    }

    @Test("The mark is honoured only from a sentry whose hello lists every tc probe")
    func requiresTCProbes() {
        let all: [String: Any] = ["probes": ["security_bprm_check", "tc_modify_qdisc", "tc_new_tfilter", "tc_ctl_action"]]
        #expect(KernelSentryService.watchesTrafficControl(all))
        #expect(!KernelSentryService.watchesTrafficControl(["probes": ["tc_modify_qdisc", "tc_new_tfilter"]]))
        #expect(!KernelSentryService.watchesTrafficControl(["probes": [String]()]))
        #expect(!KernelSentryService.watchesTrafficControl([:]))
    }

    @Test("Disarmed probes revoke the exemption: tc may no longer be watched")
    func disarmedProbesRevoke() {
        let pid = UUID()
        let svc = KernelSentryService.shared
        let old = svc.containerDirectProvider
        defer { svc.containerDirectProvider = old; svc.rearmContainerMark(profileID: pid)
                svc.noteContainerMark(profileID: pid, active: false) }
        svc.containerDirectProvider = { $0 == pid }
        svc.noteContainerMark(profileID: pid, active: true)
        let bridge = SentryBridge(profileID: pid, requirement: .bestEffort, restoring: false)
        bridge.handle(["type": "heartbeat", "seq": 1, "probes": ["armed": 30, "total": 30, "missed": 0]])
        #expect(VMNetSwitch.shared.isContainerTrafficDirect(profileID: pid))
        bridge.handle(["type": "heartbeat", "seq": 2, "probes": ["armed": 27, "total": 30, "missed": 0]])
        #expect(!VMNetSwitch.shared.isContainerTrafficDirect(profileID: pid))
    }

    @Test("Not applied without the sentry, or under a policy with request-level rules")
    func effective() {
        var p = bromure_ac.Profile(name: "c", tool: .claude, authMode: .token)
        p.containerTrafficDirect = true
        #expect(!p.effectiveContainerTrafficDirect)                             // sentry off
        p.kernelSentry = .bestEffort
        // Finding (CWE-693): "Firewall pane drops the container-traffic
        // switch while the exemption still applies". A Bromure Firewall
        // workspace has no switch for it: a flag left set doesn't apply.
        #expect(!p.usesOpenShellPolicy)
        #expect(!p.effectiveContainerTrafficDirect)
        p.networkPolicy = "version: 1\nnetwork_policies: {}\n"                // OpenShell, where its switch is
        #expect(p.effectiveContainerTrafficDirect)
        p.networkPolicy = """
        version: 1
        network_policies:
          gh:
            endpoints:
              - host: api.github.com
                port: 443
                protocol: rest
                rules:
                  - allow: { method: GET, path: "/**" }
            binaries: [{ path: /usr/bin/curl }]
        """
        #expect(!p.resolvedEgressPolicy.inspectedPorts.isEmpty)
        #expect(!p.effectiveContainerTrafficDirect)
    }
}
