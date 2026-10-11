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
///
/// The keep-awake lasts only the boot wait: it ends when the budget runs out
/// (checked or not — a caller stuck in a call that never returns can't hold
/// the Mac awake past it), on `release()` (the workspace answered; what
/// follows — a clone, the run — isn't "starting"), or when it's dropped.
final class BootBudget: @unchecked Sendable {
    private let deadline: TimeInterval
    private let clock: () -> TimeInterval
    private let lock = NSLock()
    private var activity: NSObjectProtocol?

    /// `clock`: seconds of awake time (the default doesn't advance while the
    /// Mac sleeps). `holdAwake`: hold off idle sleep and App Nap until the
    /// budget runs out or is released.
    init(seconds: TimeInterval, reason: String, holdAwake: Bool = true,
         clock: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) {
        self.clock = clock
        deadline = clock() + seconds
        activity = holdAwake
            ? ProcessInfo.processInfo.beginActivity(options: [.userInitiated, .idleSystemSleepDisabled],
                                                    reason: reason)
            : nil
        if holdAwake {
            // DispatchTime stops while the Mac sleeps, like the budget.
            DispatchQueue.global().asyncAfter(deadline: .now() + seconds) { [weak self] in self?.release() }
        }
    }

    deinit { release() }

    /// Stop keeping the Mac awake (idempotent).
    func release() {
        lock.lock()
        let a = activity
        activity = nil
        lock.unlock()
        if let a { ProcessInfo.processInfo.endActivity(a) }
    }

    /// Whether the Mac is still being kept awake for this budget.
    var holdsAwake: Bool { lock.lock(); defer { lock.unlock() }; return activity != nil }

    /// Time is left. Once it isn't, the keep-awake ends.
    var remains: Bool {
        let left = clock() < deadline
        if !left { release() }
        return left
    }
}
