import Foundation

/// Workspaces whose boot `launch` has started but not finished. Between the
/// two, the disk is being cloned, prepared and opened by
/// Virtualization.framework, yet the VM isn't in `runningSessions` until
/// `registerSession` — so a delete, reset or revert that only looked there
/// pulled the images out from under a booting VM. Begun before `launch`
/// returns, ended when the boot registers or fails.
@MainActor final class BootsInFlight {
    private var ids: Set<UUID> = []

    /// Marks a boot under way; false when one already is (one boot per disk).
    func begin(_ id: UUID) -> Bool { ids.insert(id).inserted }
    func end(_ id: UUID) { ids.remove(id) }
    func contains(_ id: UUID) -> Bool { ids.contains(id) }

    /// The workspace's disk and home are open, or about to be.
    func diskInUse(_ id: UUID, running: Bool) -> Bool { running || ids.contains(id) }
}
