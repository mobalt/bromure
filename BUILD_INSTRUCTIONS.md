# Build Instructions

## Prerequisites

- macOS 14.0+, Apple Silicon Mac
- Xcode Command Line Tools (`xcode-select --install`)
- An [Apple Developer Program](https://developer.apple.com/programs/) membership ($99/year) — required for the entitlements and provisioning profile

## GhosttyKit (bromure-ac native terminals)

`bromure-ac` links **GhosttyKit** (libghostty) as an SPM binary target at
`vendor/GhosttyKit.xcframework`. It is **not** committed; `./build.sh` builds
it automatically on first run via `tools/build-ghostty.sh`, which:

- downloads a pinned zig toolchain into `~/.cache/bromure-ghostty`,
- fetches ghostty at the commit pinned in `tools/ghostty.commit`,
- builds `GhosttyKit.xcframework` and stages it (plus terminal runtime
  resources) into `vendor/`.

First build takes a few minutes; afterwards it's a no-op keyed on the pinned
commit. `swift build` / `swift test` also need `vendor/` present — run
`./tools/build-ghostty.sh` once if you skip `build.sh`. CI should cache
`~/.cache/bromure-ghostty` (the zig toolchain and source); if it caches
`vendor/` too, key it on `tools/ghostty.commit` **and** the `BUILD_FLAGS` in
`tools/build-ghostty.sh` — not on the commit alone — and still run the script
(or `build.sh`, which always does): it compares the framework's stamp
(`vendor/GhosttyKit.xcframework/.bromure-ghostty-commit`, commit + flags) and
rebuilds a stale one, e.g. one built before `-Dsentry=false`.
The script self-heals two Xcode 26 toolchain issues: SDKs whose tbds dropped
the `arm64-macos` slice (zig #31658) and libtool dropping zig's misaligned
archive members; see the comments in `tools/build-ghostty.sh`.

## Apple Developer Entitlements

Bromure requires several entitlements that must be registered in your Apple Developer account. Go to [Certificates, Identifiers & Profiles](https://developer.apple.com/account/resources/) and configure the following.

### 1. Register an App ID

Under **Identifiers**, create an App ID with:

- **Bundle ID:** Create a new bundle ID (I'm using `io.bromure.app`)
- **App ID Prefix / Team ID:** your 10-character team ID (e.g. `W3RD8G85BC`)

Enable these **Capabilities** on the App ID:

| Capability | Why |
|---|---|
| **iCloud** (CloudKit + iCloud Documents) | Syncing profile definitions across Macs |
| **Network Extensions** / vmnet | Host-side network filtering for LAN isolation |

### 2. Create a Provisioning Profile

Under **Profiles**, create a **Developer ID** provisioning profile:

- **Type:** Developer ID Application
- **App ID:** The Bundle ID you picked (`io.bromure.app` in my case)
- **Certificate:** your "Developer ID Application" certificate (see below)

Download the `.provisionprofile` file and save it as:

```
bromure.provisionprofile      # in the repository root
```

The build scripts embed this into the app bundle as `Contents/embedded.provisionprofile`. Without it, iCloud and vmnet entitlements will not work at runtime.

### 3. Create a Developer ID Certificate

Under **Certificates**, if you don't already have one, create a **Developer ID Application** certificate. This is the identity used for code signing. You can list your available identities with:

```bash
security find-identity -v -p codesigning
```

Look for a line like:

```
"Developer ID Application: Your Name (TEAM_ID)"
```

## Entitlements File

The entitlements are defined in `Sources/CLI/SafariSandbox.entitlements`. For reference, it requests:

| Entitlement | Purpose |
|---|---|
| `com.apple.security.virtualization` | Virtualization.framework access |
| `com.apple.application-identifier` | App identity (must match provisioning profile) |
| `com.apple.developer.team-identifier` | Team identity |
| `com.apple.developer.ubiquity-container-identifiers` | iCloud Documents container |
| `com.apple.developer.icloud-container-identifiers` | iCloud container |
| `com.apple.developer.icloud-services` | iCloud services |
| `com.apple.developer.icloud-container-environment` | iCloud production environment |
| `com.apple.developer.networking.vmnet` | vmnet framework for network filtering |
| `com.apple.security.device.camera` | Webcam passthrough to VM |
| `com.apple.security.device.audio-input` | Microphone passthrough to VM |

You should not need to edit this file. To sign under a different team or bundle ID, see [Building under your own team](#building-under-your-own-team) below.

## Building under your own team

The tracked entitlements and Info.plist carry the upstream team ID and bundle IDs. Don't edit them: the build scripts write your identity into build-dir copies instead, driven by two variables.

| Variable | Description |
|---|---|
| `BROMURE_TEAM_ID` | Your 10-character Apple Developer team ID |
| `BROMURE_BUNDLE_ID` | The bundle ID you registered (one per target you build) |

They set `com.apple.application-identifier`, `com.apple.developer.team-identifier` and the keychain access group in the entitlements, and `CFBundleIdentifier` in the Info.plist (`scripts/stamp-identity.sh`). Your provisioning profile must be for that same team and bundle ID. iCloud container identifiers are not rewritten; if your team registered its own, edit the tracked entitlements locally.

Put them, with your signing identity, in `.env.local` at the repository root. It is gitignored and sourced by both `build.sh` and `package.sh`; a variable already set in the environment wins over the file.

```bash
# .env.local
CODESIGN_IDENTITY="Developer ID Application: Your Name (ABC123XYZ)"
BROMURE_TEAM_ID=ABC123XYZ
BROMURE_BUNDLE_ID=com.example.bromure-ac
BROMURE_DEV=1
```

Then `./build.sh bromure-ac` signs under your team with no other flags. Since the bundle ID is per target, keep one `.env.local` per target you build, or pass `BROMURE_BUNDLE_ID=… ./build.sh bromure` on the command line to override it.

### Dev flavor (`BROMURE_DEV=1`)

With `BROMURE_DEV=1` in `.env.local` (or the environment), `./build.sh bromure-ac` builds a copy that can run next to an installed release without touching it:

- named "Bromure AC Dev" in the menu bar and Dock ("Bromure Dev" for the browser, "Bromure Sidecar Dev" for Sidecar); the icon is unchanged;
- its data in `~/Library/Application Support/BromureACDev` and `~/Library/Logs/BromureACDev` (`BromureSupportDirName`), so it never reads or locks the release's data. A build signed by another team gets a different keychain master key and couldn't decrypt the release's files anyway;
- Sparkle's scheduled checks and automatic installs off, so a release update can never replace it. "Check for Updates…" still works by hand.

The bundle's file name is unchanged (`Bromure Agentic Coding.app`). The flavor is independent of the identity: a dev build under the upstream team is fine for local testing, and a release-flavored build under your own team is what `package.sh` produces.

## File Layout

```
bromure/
  bromure-ac.provisionprofile        # downloaded from Apple Developer portal (gitignored; build.sh embeds it)
  .env.local                         # your signing identity and flavor (gitignored)
  Sources/Browser/                   # Bromure: entitlements, Info.plist
  Sources/AgentCoding/               # Bromure Agentic Coding: entitlements, Info.plist
  build.sh                           # local build: bromure | bromure-ac | sidecar
  package.sh                         # release build + notarization + DMG
  scripts/stamp-identity.sh          # writes your team/bundle ID into build-dir copies
```

## Building

### Development Build (`build.sh`)

Builds the binary and creates a `.app` bundle with code signing:

```bash
CODESIGN_IDENTITY="Developer ID Application: Your Name (TEAM_ID)" ./build.sh            # Bromure
CODESIGN_IDENTITY="Developer ID Application: Your Name (TEAM_ID)" ./build.sh bromure-ac # Bromure Agentic Coding
```

The target is `bromure` (default), `bromure-ac` or `sidecar`. With `BROMURE_DEV=1` set, the build is the [dev flavor](#dev-flavor-bromure_dev1).

If `CODESIGN_IDENTITY` is not set, it falls back to ad-hoc signing (`-`), which is sufficient for local testing but will not satisfy Gatekeeper or enable iCloud/vmnet.

**Environment variables:**

| Variable | Required | Description |
|---|---|---|
| `CODESIGN_IDENTITY` | No (defaults to `-`) | Code signing identity |
| `BROMURE_TEAM_ID`, `BROMURE_BUNDLE_ID` | No | Sign under your own team ([above](#building-under-your-own-team)) |
| `BROMURE_DEV` | No | `1` for the dev flavor ([above](#dev-flavor-bromure_dev1)) |

All of them can live in `.env.local`. The bundle is created at `.build/arm64-apple-macosx/release/<App name>.app` (`Bromure.app`, `Bromure Agentic Coding.app`, `Bromure Sidecar.app`). `swift build` alone does not refresh it; run `build.sh`.

### Release Build (`package.sh`)

Builds, signs, notarizes, and packages into a DMG for distribution:

```bash
DEVELOPER_ID="Developer ID Application: Your Name (TEAM_ID)" \
APPLE_ID="you@example.com" \
TEAM_ID="ABC123XYZ" \
APP_PASSWORD="xxxx-xxxx-xxxx-xxxx" \
./package.sh
```

**Environment variables:**

| Variable | Required | Description |
|---|---|---|
| `DEVELOPER_ID` | Yes | Code signing identity (same format as `CODESIGN_IDENTITY`) |
| `APPLE_ID` | For notarization | Your Apple ID email |
| `TEAM_ID` | For notarization | Your 10-character Apple Developer team ID |
| `APP_PASSWORD` | For notarization | App-specific password ([generate here](https://appleid.apple.com) > Sign-In and Security > App-Specific Passwords) |
| `BROMURE_TEAM_ID`, `BROMURE_BUNDLE_ID` | No | Sign under your own team ([above](#building-under-your-own-team)) |

`package.sh` reads `.env.local` too.

If `APPLE_ID`, `TEAM_ID`, or `APP_PASSWORD` are missing, the script will still sign and package but skip notarization. The resulting DMG will trigger Gatekeeper warnings on other Macs.

The DMG is created at `.build/arm64-apple-macosx/release/Bromure.dmg`.
