import Foundation
import AppKit

/// Consent broker for the `lockfilePrompt` supply-chain layer (and
/// any other ask-the-user paths the policy fires). Same shape as
/// `GuardrailsConsentBroker` — actor with coalescing, in-memory
/// grants, profile-name plumbing — kept distinct so the snapshot /
/// approvals UI can list "Supply chain decisions" separately from
/// "Guardrail decisions". They're conceptually different
/// (intercepting versus rejecting agent intent) even when the
/// broker code shape is identical.
public actor SupplyChainConsentBroker {
    public enum Decision: Sendable {
        case deny
        case allowOnce
        case allow15min
        case allowSession
    }

    public struct Grant: Sendable {
        public let expiration: Date
        public let scopeDisplayName: String
        public let isSessionScoped: Bool
    }

    public enum DecisionKind: Sendable {
        case allow
        case deny
    }

    public struct LiveEntry: Sendable {
        public let profileID: UUID
        public let scope: String
        public let kind: DecisionKind
        public let expiration: Date
        public let scopeDisplayName: String
        public let isSessionScoped: Bool
    }

    private struct DenyMemory: Sendable {
        let expiration: Date
        let scopeDisplayName: String
    }

    private static func storeKey(profileID: UUID, scope: String) -> String {
        profileID.uuidString + "|" + scope
    }

    private static func splitStoreKey(_ s: String) -> (UUID, String)? {
        guard let pipe = s.firstIndex(of: "|") else { return nil }
        let uuidStr = String(s[..<pipe])
        let scope = String(s[s.index(after: pipe)...])
        guard let uuid = UUID(uuidString: uuidStr) else { return nil }
        return (uuid, scope)
    }

    private var grants: [String: Grant] = [:]
    private var denies: [String: DenyMemory] = [:]
    private static let denyTTL: TimeInterval = 60
    private var pending: [String: [CheckedContinuation<Bool, Never>]] = [:]
    private var profileNames: [UUID: String] = [:]

    public init() {}

    public func setProfileName(_ name: String, for profileID: UUID) {
        profileNames[profileID] = name
    }
    public func clearProfileName(for profileID: UUID) {
        profileNames.removeValue(forKey: profileID)
    }

    /// Returns true iff the supply-chain action should proceed.
    ///
    /// - Parameters:
    ///   - profileID: profile owning the request.
    ///   - scope: stable identifier for the grant scope. Convention:
    ///     `"lockfile:<ecosystem>"` for the npm-ci-style bypass,
    ///     `"override:<ecosystem>:<pkg>:<version>"` if we ever ask
    ///     the user to override a specific block.
    ///   - scopeDisplayName: shown in the dialog title.
    ///   - detail: shown verbatim in the dialog body — exact
    ///     description of what's about to happen ("npm ci will fetch
    ///     187 packages pinned by package-lock.json…").
    public func consent(profileID: UUID,
                        scope: String,
                        scopeDisplayName: String,
                        detail: String) async -> Bool {
        let key = Self.storeKey(profileID: profileID, scope: scope)
        let checkedAt = Date()

        FileHandle.standardError.write(Data(
            "[supply-chain-consent] check \(scope) for profile \(profileID.uuidString.prefix(8))\n".utf8))

        if let mem = denies[key], mem.expiration > checkedAt {
            FileHandle.standardError.write(Data(
                "[supply-chain-consent] live deny for \(scope) — auto-deny\n".utf8))
            return false
        } else if denies[key] != nil {
            denies.removeValue(forKey: key)
        }

        if let g = grants[key], g.expiration > checkedAt {
            FileHandle.standardError.write(Data(
                "[supply-chain-consent] live grant for \(scope) — auto-allow\n".utf8))
            return true
        } else if grants[key] != nil {
            grants.removeValue(forKey: key)
        }

        if pending[key] != nil {
            return await withCheckedContinuation { cont in
                pending[key, default: []].append(cont)
            }
        }
        pending[key] = []

        let profileName = profileNames[profileID] ?? "(unknown profile)"
        // Non-modal, deadline → deny; fat client / terminal when attached.
        let title = String(format: NSLocalizedString(
            "Pass through %@ from workspace “%@”?",
            comment: "Supply-chain bypass prompt"), scopeDisplayName, profileName)
        let choices = [NSLocalizedString("Allow for 15 minutes", comment: ""),
                       NSLocalizedString("Allow once", comment: ""),
                       NSLocalizedString("Allow for the rest of the session", comment: ""),
                       NSLocalizedString("Don't allow", comment: "")]
        let idx = await ConsentPrompt.choose(profileID: profileID, title: title, message: detail,
                                             choices: choices, denyIndex: choices.count - 1,
                                             style: .warning)
        let decision: Decision
        switch idx {
        case 0:  decision = .allow15min
        case 1:  decision = .allowOnce
        case 2:  decision = .allowSession
        default: decision = .deny
        }
        // Grant lifetimes start at the answer.
        let now = Date()

        let allow: Bool
        switch decision {
        case .deny:
            denies[key] = DenyMemory(
                expiration: now.addingTimeInterval(Self.denyTTL),
                scopeDisplayName: scopeDisplayName)
            allow = false
        case .allowOnce:
            allow = true
        case .allow15min:
            grants[key] = Grant(
                expiration: now.addingTimeInterval(15 * 60),
                scopeDisplayName: scopeDisplayName,
                isSessionScoped: false)
            allow = true
        case .allowSession:
            grants[key] = Grant(
                expiration: .distantFuture,
                scopeDisplayName: scopeDisplayName,
                isSessionScoped: true)
            allow = true
        }

        let waiters = pending[key] ?? []
        pending.removeValue(forKey: key)
        for w in waiters { w.resume(returning: allow) }
        return allow
    }

    // MARK: Unverified packages

    /// The scope every unverified package of a workspace shares: "all
    /// unverified packages for 15 minutes" / "for the rest of the session".
    static let anyUnverifiedScope = "verify-unavailable:*"

    static func unverifiedScope(ecosystem: String, name: String, version: String) -> String {
        "verify-unavailable:\(ecosystem):\(name):\(version)"
    }

    /// The choices of the unverified-package question, in order; the last
    /// is the deny (also no answer, Esc, closing the panel).
    enum UnverifiedChoice: Int, CaseIterable {
        case allowPackage, allowAll15min, denyAllSession, denyPackage
    }

    /// Workspaces with an unverified-package question open, and who waits
    /// behind it: one question at a time, so an "all packages" answer
    /// settles the rest without asking (a `uv sync` used to raise one panel
    /// per package, all at once).
    private var unverifiedBusy: Set<UUID> = []
    private var unverifiedWaiters: [UUID: [CheckedContinuation<Void, Never>]] = [:]

    /// A package no reputation source could vet: may it install? Allowing
    /// or refusing "this package" covers that version for the session (an
    /// installed package is installed — a timed grant on it meant nothing);
    /// the other two answers cover every unverified package of the
    /// workspace. No answer is a refusal of this package for a minute.
    public func consentUnverified(profileID: UUID, ecosystem: String, name: String, version: String,
                                  why: String) async -> Bool {
        let pkgKey = Self.storeKey(profileID: profileID,
                                   scope: Self.unverifiedScope(ecosystem: ecosystem, name: name, version: version))
        let allKey = Self.storeKey(profileID: profileID, scope: Self.anyUnverifiedScope)
        if let known = decided(pkgKey) ?? decided(allKey) { return known }

        // One question at a time per workspace; the answer to the one
        // before may have settled this one.
        while unverifiedBusy.contains(profileID) {
            await withCheckedContinuation { unverifiedWaiters[profileID, default: []].append($0) }
        }
        if let known = decided(pkgKey) ?? decided(allKey) {
            wakeNextUnverified(profileID)
            return known
        }
        unverifiedBusy.insert(profileID)

        let waiting = unverifiedWaiters[profileID]?.count ?? 0
        let profileName = profileNames[profileID] ?? "(unknown profile)"
        let label = "\(name) \(version)"
        let title = String(format: NSLocalizedString(
            "Install %@ from workspace “%@” without a reputation check?",
            comment: "Supply chain: unverified package prompt title (package and version, workspace)"), label, profileName)
        var message = String(format: NSLocalizedString(
            "Bromure couldn't vet %@ package %@: %@ Installing it means accepting a package that wasn't checked against your configured reputation sources.",
            comment: "Supply chain: unverified package prompt (ecosystem, package and version, why)"), ecosystem, label, why)
        if waiting > 0 {
            message += "\n\n" + String(format: NSLocalizedString(
                "%d more unverified packages are waiting for an answer.",
                comment: "Supply chain: unverified packages queued behind this prompt"), waiting)
        }
        let choices = UnverifiedChoice.allCases.map { c -> String in
            switch c {
            case .allowPackage:
                return String(format: NSLocalizedString("Allow %@", comment: "Supply chain: allow this one package"), label)
            case .allowAll15min:
                return NSLocalizedString("Allow all unverified packages for 15 minutes", comment: "Supply chain")
            case .denyAllSession:
                return NSLocalizedString("Don't allow unverified packages for the rest of the session", comment: "Supply chain")
            case .denyPackage:
                return String(format: NSLocalizedString("Don't allow %@", comment: "Supply chain: refuse this one package"), label)
            }
        }
        let idx = await ConsentPrompt.choose(profileID: profileID, title: title, message: message,
                                             choices: choices, denyIndex: UnverifiedChoice.denyPackage.rawValue,
                                             style: .warning)
        let allow = record(UnverifiedChoice(rawValue: idx ?? -1) ?? .denyPackage, pkgKey: pkgKey, allKey: allKey,
                           label: label, now: Date())
        unverifiedBusy.remove(profileID)
        wakeNextUnverified(profileID)
        return allow
    }

    /// A live decision for `key`: true (grant), false (deny), nil (ask).
    private func decided(_ key: String, now: Date = Date()) -> Bool? {
        if let d = denies[key] {
            if d.expiration > now { return false }
            denies.removeValue(forKey: key)
        }
        if let g = grants[key] {
            if g.expiration > now { return true }
            grants.removeValue(forKey: key)
        }
        return nil
    }

    private func wakeNextUnverified(_ profileID: UUID) {
        guard var w = unverifiedWaiters[profileID], !w.isEmpty else { return }
        let next = w.removeFirst()
        unverifiedWaiters[profileID] = w.isEmpty ? nil : w
        next.resume()
    }

    /// Store an answer to the unverified-package question; true = install.
    func record(_ choice: UnverifiedChoice, pkgKey: String, allKey: String, label: String, now: Date) -> Bool {
        let all = NSLocalizedString("all unverified packages", comment: "Supply chain: approvals list entry")
        switch choice {
        case .allowPackage:
            grants[pkgKey] = Grant(expiration: .distantFuture, scopeDisplayName: label, isSessionScoped: true)
            return true
        case .allowAll15min:
            grants[allKey] = Grant(expiration: now.addingTimeInterval(15 * 60), scopeDisplayName: all,
                                   isSessionScoped: false)
            return true
        case .denyAllSession:
            denies[allKey] = DenyMemory(expiration: .distantFuture, scopeDisplayName: all)
            return false
        case .denyPackage:
            denies[pkgKey] = DenyMemory(expiration: now.addingTimeInterval(Self.denyTTL), scopeDisplayName: label)
            return false
        }
    }

    public func snapshot() -> [LiveEntry] {
        let now = Date()
        var out: [LiveEntry] = []
        for (k, g) in grants where g.expiration > now {
            guard let (pid, scope) = Self.splitStoreKey(k) else { continue }
            out.append(LiveEntry(
                profileID: pid, scope: scope,
                kind: .allow,
                expiration: g.expiration,
                scopeDisplayName: g.scopeDisplayName,
                isSessionScoped: g.isSessionScoped))
        }
        for (k, d) in denies where d.expiration > now {
            guard let (pid, scope) = Self.splitStoreKey(k) else { continue }
            out.append(LiveEntry(
                profileID: pid, scope: scope,
                kind: .deny,
                expiration: d.expiration,
                scopeDisplayName: d.scopeDisplayName,
                isSessionScoped: false))
        }
        return out.sorted { $0.scopeDisplayName < $1.scopeDisplayName }
    }

    public func revoke(profileID: UUID, scope: String) {
        let key = Self.storeKey(profileID: profileID, scope: scope)
        grants.removeValue(forKey: key)
        denies.removeValue(forKey: key)
    }

    public func revokeAll(profileID: UUID) {
        let prefix = profileID.uuidString + "|"
        for k in grants.keys where k.hasPrefix(prefix) {
            grants.removeValue(forKey: k)
        }
        for k in denies.keys where k.hasPrefix(prefix) {
            denies.removeValue(forKey: k)
        }
    }

    public func revokeEverything() {
        grants.removeAll()
        denies.removeAll()
    }
}
