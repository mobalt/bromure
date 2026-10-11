import Foundation

/// How long an unattended start (an automation firing, a board task) waits
/// for its workspace to come up — counted in time the Mac is AWAKE, and
/// keeping it awake meanwhile.
///
/// A wall-clock deadline failed every run that fired on a sleeping Mac: the
/// fire comes from a dark wake, the VM starts booting, the Mac goes back to
/// sleep, and on the next wake the 180 s were long gone — "the workspace
/// did not boot in time" for a workspace that was never given the time. A
/// suspended workspace restores in seconds and slipped through; a cold boot
/// of one that's OFF doesn't.
final class BootBudget {
    private let deadline: TimeInterval
    private let clock: () -> TimeInterval
    private let activity: NSObjectProtocol?

    /// `clock`: seconds of awake time (the default doesn't advance while the
    /// Mac sleeps). `holdAwake`: hold off idle sleep and App Nap until the
    /// budget is released.
    init(seconds: TimeInterval, reason: String, holdAwake: Bool = true,
         clock: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) {
        self.clock = clock
        deadline = clock() + seconds
        activity = holdAwake
            ? ProcessInfo.processInfo.beginActivity(options: [.userInitiated, .idleSystemSleepDisabled],
                                                    reason: reason)
            : nil
    }

    deinit {
        if let activity { ProcessInfo.processInfo.endActivity(activity) }
    }

    /// Time is left.
    var remains: Bool { clock() < deadline }
}
