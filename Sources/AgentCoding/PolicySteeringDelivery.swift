import Foundation

/// Where `PolicySteering`'s notes go. Claude reads them mid-turn: its
/// PostToolUse / UserPromptSubmit hook (`agent-status.sh policy`) claims the
/// files dropped in `~/.bromure/policy-notes/` and hands their text to the
/// model as context, right after the tool call that hit the block. The other
/// agents' hooks only report status, so their note is typed into the tab as
/// one line once the agent's turn is over.
extension ACAppDelegate {
    static let policyNotesDir = "/home/ubuntu/.bromure/policy-notes"

    func wirePolicySteering(_ engine: MitmEngine) {
        let steering = PolicySteering.shared
        let modes = OpenShellAdvisorModeCache.shared
        steering.enabledProvider = { modes.tellsAgentOnDeny($0) }
        steering.openShellProvider = { [weak engine] in engine?.guardrailsConfig(for: $0)?.egressPolicy?.openShell }
        steering.advisorOnProvider = { modes.mode(for: $0) != .off }
        steering.deliver = { [weak self] pid, window, text, soleOnly in
            Task { @MainActor in
                self?.deliverPolicyNote(profileID: pid, window: window, text: text, soleOnly: soleOnly)
            }
        }
    }

    @MainActor
    func deliverPolicyNote(profileID: UUID, window: Int?, text: String, soleOnly: Bool) {
        // This Mac's VMs only (an attached Sidecar runs its own policy).
        guard runningSessions[profileID] != nil else { return }
        let live = agentSessionStore.sessions.filter {
            $0.profileID == profileID && $0.windowIndex != nil && !$0.isDeleted && !$0.isArchived
                && !$0.hasEnded && $0.agentAlive != false
        }
        var targets: [(window: Int, tool: Profile.Tool)]
        if let window {
            // A tab no session owns (an agent started from the shell) whose
            // agent's hook named it: Claude is the one that reports a pid.
            targets = [(window, live.first { $0.windowIndex == window }?.tool ?? .claude)]
        } else {
            targets = live.compactMap { s in s.windowIndex.map { ($0, s.tool) } }
            // An agent the app doesn't list as a session still reported its
            // tab through its hooks (Claude's are the ones that do).
            for w in PolicySteering.shared.agentWindows(profileID: profileID).sorted()
            where !targets.contains(where: { $0.window == w }) {
                targets.append((w, .claude))
            }
            if soleOnly && targets.count != 1 { return }
        }
        PolicySteering.log("deliver to \(targets.isEmpty ? "no agent tab" : targets.map { "w\($0.window) (\($0.tool.rawValue))" }.joined(separator: ", "))")
        for t in targets {
            if t.tool == .claude {
                writePolicyNote(profileID: profileID, window: t.window, text: text)
            } else {
                queueTypedPolicyNote(profileID: profileID, window: t.window, text: text)
            }
        }
    }

    /// One file per note, moved into place whole, so the hook never reads
    /// half of one; owned by the agent's user so it can claim them.
    @MainActor
    private func writePolicyNote(profileID: UUID, window: Int, text: String) {
        let d = Self.policyNotesDir
        let cmd = """
        d=\(d); mkdir -p "$d" && chown ubuntu:ubuntu "$d" 2>/dev/null; chmod 700 "$d"; \
        t="$d/.w\(window).$$"; printf '%s\\n' \(CodingTaskEngine.shellQuote(text)) > "$t" \
        && chown ubuntu:ubuntu "$t" 2>/dev/null; mv -f "$t" "$d/w\(window)-$(date +%s%N).note"
        """
        Task { _ = try? await guestExec(profileID: profileID, command: cmd, timeout: 10) }
    }

    /// Notes owed to non-Claude tabs, typed once the tab's agent is idle.
    private static var typedNotes: [String: [String]] = [:]

    @MainActor
    private func queueTypedPolicyNote(profileID: UUID, window: Int, text: String) {
        let key = "\(profileID.uuidString)|\(window)"
        let first = Self.typedNotes[key] == nil
        Self.typedNotes[key, default: []].append(text)
        guard first else { return }
        Task { @MainActor [weak self] in
            // Wait for the turn to end (up to 15 minutes); typing into a
            // working agent would queue a new prompt behind its turn anyway.
            let deadline = Date().addingTimeInterval(900)
            while Date() < deadline {
                let status = self?.pane(for: profileID)?.model.tabs.first { $0.index == window }?.agentStatus
                if status == nil || status == .done { break }
                try? await Task.sleep(for: .seconds(3))
            }
            let notes = Self.typedNotes.removeValue(forKey: key) ?? []
            guard let self, let head = notes.first else { return }
            let line = notes.count == 1 ? head
                : head + " (\(notes.count - 1) more action\(notes.count == 2 ? " was" : "s were") blocked the same way.)"
            let target = self.agentSessionStore.session(profileID: profileID, windowIndex: window)
                .flatMap { AgentSessionEngine.paneTarget($0) } ?? .index(window)
            _ = await CodingTaskEngine.typeWhenFreeResult(self, profileID: profileID, target: target,
                                                          text: line, patience: 300)
        }
    }
}
