# Software Supply Chain Auditor

Software Supply Chain Auditor (SSCA) is an automation solution to continuous and safe software dependency updates.

This program is designed to parse a first-party code repository, extract dependencies and their versions, then watch those dependencies for updates.
When a dependency update is detected, the source code is pulled and a diff is generated on the previous and new versions.

This differential is presented in this program as a human-gated review prior to dependency updates being merged with the first-party code repository.

The program itself is designed to never be able to take any action without explicit human authorization.
To this end, the program heavily relies on specific paths to leverage cryptographic hardware keys the user controls.

Note: *This is a work-in-progress. Check back at this repository for future updates*

## Design

### Planned features

- Web UI authentication: Password, FIDO2, OIDC (SSO)
- Multi-user review requirements
  - Admins can configure SSCA to require valid signatures from multiple users before a push is authorized.
- Block-listing of upgrades
  - Disables accepting of versions that build off of blocked version
  - Can be lifted by appropriate permissions once a new version has desired code
- Notifications
  - Email only (for now)
- Single configuration file
  - All SSCA configurations stored in a single JSON file (editable via CLI or by admin-privileged users)
- LLM summarization
  - Configure custom provider to retrieve a summarization of upstream source diffs
  - Summarization is attached to the review
  - A brief version of the summary sent with the notification
- Supported languages
  - Golang

### Flow

- Detect upstream dependency version upgrade is available
  - Using admin-configured language-specific trusted upstream sources
  - Polling upstream at configured intervals
  - Language-specific parsers to pull all dependencies (including transitive)
- Pull source of new upstream version
- Pull source of previous version
- Generate diff of source code of the dependency
- Optional: Call LLM provider with diff to generate a summary
- Publish diff for human review
- Send notifications to configured users watching the dependency
- User logs in to web interface
- User reviews the diff
- User signs the diff and the first-party repository code change commit
- System creates PR to configured branch in first-party repository

### Signing

The SSCA server itself has no ability to push valid changes to the source repositories.

The SSCA server acts as a transport for the signed commit.
It does not construct, modify, re-sign, or stage commits.
Its only role in the push path is to deliver the user-signed commit to the repository.

Because of this, it is required to enforce signatures in the git provider to prevent SSCA from pushing arbitrary changes itself.

The client side signing requires a local python script to bridge SSCA to a local GPG agent.
This bridge is required since commits are generated in the browser and need a proper root of trust to sign off of (and browsers lack sufficient secure methods to interact with local keys like Yubikeys)

File is located at: `resources/ssca-gpg-bridge.py`

This script is used to expose only the desired key for signing requests.
Ideally this key is hardware-key backed requiring user-presence to permit creating a signature.

The script requires no extra dependencies besides python3 itself and is minimal and clear to permit user-review before installation.

The bridge script is designed with the following invariants:

- Exposes only the signing operation. No key export, no key listing, no other GPG operations.
- Token-gated: only the client presenting the correct pre-shared secret may request a signature.
- Stateless: no data is stored between requests. Each request is independent.
- Key-isolated: only the single configured key is accessible.
- Minimal and auditable: no dependencies beyond the system Python and GPG. A user can verify by inspection that it does nothing beyond validate the token and invoke gpg --detach-sign.

## Architecture

Three components:

- Primary SSCA server: single binary
- Client side code: WASM binary (served by SSCA server)
- Javascript stub: deployed separately, verifies WASM binary

### Primary SSCA server

This component is the central coordinator and server.

Purposes:

- Serves all web server files (including WASM)
- Watches upstream dependencies
- Pulls upstream versions
- Generates source code differentials
- Generates reviews
- Brokers user-created commits to first-party repositories

### WASM binary

This component contains all the client side code that runs in the user's browser.

Purposes:

- Handles ALL communication between user and the SSCA server.
- Independently verifies all review material presented to it from the SSCA server.

Verification of review material:

The WASM client does not trust the SSCA server's representation of a dependency update.

Before presenting any material to the user for review, the WASM independently verifies:

- **Source integrity**:
  The upstream source code shown to the user matches the canonical source for the claimed version.
  The server cannot substitute or inject code into the source being reviewed.

- **Diff accuracy**:
  The differential shown to the user accurately represents the change between the currently-pinned version and the proposed version.
  The server cannot show a benign diff that does not match the actual change.

- **Commit binding**:
  The exact bytes that will be signed by the user's hardware key are the same bytes the user is reviewing.
  The user signs what they see, and nothing else.
  The server cannot alter the commit between review and signing.

The net effect: the user's signature is a cryptographic attestation that "I reviewed this exact change and I authorize it."
The SSCA server can influence what is suggested, but it cannot influence what is signed.

### Javascript Stub

To ensure the SSCA server cannot serve malicious client-side code, the stub will contain a long lived public key.
The corresponding private key is held by me (the developer) and used to sign the WASM binary at *compile time*.

Purpose:

- Pull the live WASM binary from the actual server.
- Verify it has not been tampered (verify signature).
- Start the WASM

In order to maintain the chain of integrity, the stub must be served from a different component than the SSCA server itself and must be the first thing a user browses to.

Usage:

- Served from supplied index.html from the same domain (user browsers to /, they get the stub only)
- Files located off the SSCA server itself, ideally from a reverse proxy location

## Security

No single component in the system holds both the ability to propose a change and the authority to authorize it.
The server proposes.
The user authorizes.
The hardware key cryptographically binds the authorization to the exact proposed content.
The git provider enforces the binding.

### Threat model

The SSCA server is treated as potentially compromised at all times.
It is the untrusted middleman: it fetches upstream sources, generates diffs, and brokers commits.

A compromised server could attempt to:

- Substitute malicious source code for a dependency update
- Show the user a benign diff while committing a malicious one
- Forge or skip the user's signature
- Push changes without user authorization

The system is designed so that none of these succeed, even with a fully compromised server, provided the roots of trust below are intact.

### Roots of trust

Security roots-of-trust assumed to be fully trusted:

- Upstream dependency source code
- User's hardware-backed security key (signs changes)
- Javascript stub serving server (ensures SSCA server is not compromised)
- First-party repository git provider (gates new changes based on user signature)

All of the above must be trusted for the end to end security of this program to function correctly.

Any compromise of one of the above could result in malicious dependency updates being committed to trusted code repositories.

### Integrity chain

The system establishes a chain of verification from the user's hardware key back to the upstream source:

1. The stub verifies the WASM binary has not been tampered with.
2. The WASM independently verifies the review material (source, diff, commit) before presenting it to the user.
3. The user reviews the verified material.
4. The user's hardware key signs the exact bytes the user reviewed.
5. The git provider rejects any commit that lacks a valid signature from an authorized user.

At no point does the SSCA server have the ability to break this chain.
It can suggest, fetch, and format, but it cannot authorize.

### Human gate

The human review is not a UX convenience, it is a cryptographic gate.

The signature produced by the user's hardware key is the only thing that permits a change to land.

Without it, the SSCA server, however compromised, cannot push a valid commit.
The user's physical interaction with the hardware key (tap, PIN) is the final authorization.
