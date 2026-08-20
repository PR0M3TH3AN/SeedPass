# Nostr Communications Reference and Future Capability (2026-03-05)

Status: Research / Future Addition  
Branch target: `beta`  
Depends on:
- `docs/dev_control_center.md`
- `docs/index0_atlas_execution_plan_2026-03-05.md`
- `docs/atlas_search_graph_integration_plan_2026-03-05.md`

## 1) Goal

Capture the Nostr protocol references most relevant to a future SeedPass communications layer, then define how a managed-identity communication system could fit the current SeedPass architecture.

This document is for future implementation planning, not a statement of current shipped functionality.

## 2) Current SeedPass Baseline

SeedPass already has enough Nostr groundwork to make this future capability realistic:

1. deterministic Nostr key generation and storage as entry kind `nostr`
2. relay configuration and relay maintenance flows
3. active profile `npub` utilities
4. a current Nostr client used for SeedPass vault sync
5. `index0` atlas foundations for future communication metadata and navigation

What SeedPass does not currently have:

1. DM inbox/outbox/thread models
2. community or group chat clients
3. canonical message/conversation entry types
4. communication indexing into atlas/search
5. policy-aware communication access controls in the UI/service layer

## 3) Protocol References

Use these NIPs as the canonical starting points.

### 3.1 Private messaging

1. `NIP-04` Encrypted Direct Message
   - legacy `kind:4` DM scheme
   - explicitly marked as deprecated in favor of `NIP-17`
   - uses ECDH-derived shared secret plus AES-256-CBC payload format
   - carries significant metadata leakage warnings
   - reference:
     - https://github.com/nostr-protocol/nips/blob/master/04.md

2. `NIP-44` Encrypted Payloads (Versioned)
   - encryption format, not a messaging standard by itself
   - versioned payload format intended for signed-event contexts
   - should not be treated as a direct drop-in replacement for `NIP-04`
   - reference:
     - https://github.com/nostr-protocol/nips/blob/master/44.md

3. `NIP-59` Gift Wrap
   - metadata-obscuring event encapsulation layer
   - introduces rumors, seals, and gift wraps
   - depends on `NIP-44`
   - does not itself define the messaging UX/protocol
   - reference:
     - https://github.com/nostr-protocol/nips/blob/master/59.md

4. `NIP-17` Private Direct Messages
   - newer encrypted chat approach
   - uses `NIP-44` encryption and `NIP-59` seals/gift wraps
   - defines the direction SeedPass should prefer for future private DM support
   - reference:
     - https://github.com/nostr-protocol/nips/blob/master/17.md

### 3.2 Group and community chat

1. `NIP-28` Public Chat
   - public channel model
   - reserves event kinds `40-44` for channel create/metadata/message and basic moderation
   - useful as a baseline for open team channels or public-facing communities
   - reference:
     - https://github.com/nostr-protocol/nips/blob/master/28.md

2. `NIP-29` Relay-based Groups
   - closed-writer group model with relay-enforced rules
   - groups can be public or private for reading
   - strong candidate for institution/team chat semantics where relay policy matters
   - reference:
     - https://github.com/nostr-protocol/nips/blob/master/29.md

3. `NIP-72` Moderated Communities (Reddit Style)
   - public community model
   - defines `kind:34550` community definition and `kind:4550` approval events
   - likely more relevant for public communities than for private institutional chat
   - reference:
     - https://github.com/nostr-protocol/nips/blob/master/72.md

## 4) SeedPass-Oriented Interpretation

For SeedPass, the most relevant practical stack is:

1. private managed DMs:
   - `NIP-17` + `NIP-44` + `NIP-59`
2. public/open channels:
   - `NIP-28`
3. controlled team/group chat:
   - `NIP-29`
4. public community publishing/moderation:
   - `NIP-72`

This means:

1. do not build new private DM support on top of `NIP-04` unless compatibility mode is required
2. treat `NIP-04` as legacy interop
3. prefer `NIP-17` for future direct-message architecture
4. evaluate `NIP-29` as the strongest candidate for managed institutional group chat

## 5) Managed Identity Model

SeedPass has a unique advantage here because it can deterministically derive managed child identities.

If a Nostr identity is a managed deterministic child account:

1. the child user can operate that identity normally
2. an authorized higher-level SeedPass holder can derive the same child identity again
3. that higher-level holder can regenerate the same Nostr private key
4. supervisory recovery/access follows from key custody, not from a separate escrow system

This implies two communication classes should exist in the future:

1. personal identities
   - user-owned
   - not intended for management derivation/access
2. managed institutional identities
   - org-controlled
   - derivable by authorized higher-level key holders
   - eligible for institutional indexing, search, and oversight

## 6) How This Fits `index0`

`index0` should not store full communication bodies inline.

Recommended split:

1. canonical message or conversation content:
   - future entry kinds or encrypted conversation/message payloads
2. `index0` atlas metadata:
   - account created
   - conversation created
   - participants
   - channel/community membership metadata
   - last activity
   - message counts
   - linked documents/artifacts
   - policy/classification/visibility metadata
3. local semantic layer:
   - derived search over message bodies and linked content

That preserves the atlas role:

`Index0 is the map, not the message store.`

## 7) Recommended Future Capability Scope

### Phase A: Managed Nostr account workspace

1. load a SeedPass Nostr entry into an active comms session
2. show identity metadata, relay state, and conversation summaries
3. expose public posting and account-session controls

### Phase B: DM dashboard

1. inbox
2. conversation list
3. thread view
4. send/receive support for managed identities
5. atlas metadata indexing for conversations and message activity

Preferred protocol direction:

1. `NIP-17`
2. `NIP-44`
3. `NIP-59`
4. optional `NIP-04` compatibility only if needed

### Phase C: Institutional team chat

1. managed group/channel model
2. likely protocol evaluation centered on `NIP-29`
3. optional public/open channel support using `NIP-28`
4. public community support later via `NIP-72` if needed

### Phase D: Knowledge integration

1. link conversations to docs, secrets, tasks, and artifacts
2. surface chat activity in `index0`
3. unify search across notes, docs, links, and comms
4. support scoped agent context loading from conversations plus linked artifacts

## 8) Access Control Direction

Future communication access should remain policy-driven and consistent with SeedPass hierarchy.

Recommended rules:

1. managed institutional identities are readable by authorized higher-level key holders who can derive the same child identity
2. personal identities are not treated as institutionally recoverable by default
3. UI and service layers should make identity class explicit
4. search, export, summaries, and agent access must respect classification and partition policies
5. message excerpts shown in search/atlas should be safe by default, especially for high-risk scopes

## 9) Open Design Questions

Resolve these before implementation:

1. should full message bodies be stored as dedicated entry kinds, chunked conversation documents, or both?
2. should SeedPass mirror only managed-identity communications into canonical vault storage, or also index external/public references?
3. how should relay/group policy state be represented for `NIP-29` groups?
4. what is the minimum safe atlas metadata for private institutional conversations?
5. what should agent access look like for communication content versus conversation summaries?

## 10) Practical Recommendation

The best future direction appears to be:

1. `NIP-17` private DMs for managed identities
2. `NIP-29` for controlled team/group chat
3. `NIP-28` and `NIP-72` as optional public/community layers
4. `index0` for metadata, navigation, and oversight
5. separate canonical storage for actual message content

## 11) Source Links

Primary sources used for this reference:

1. NIP-04:
   - https://github.com/nostr-protocol/nips/blob/master/04.md
2. NIP-17:
   - https://github.com/nostr-protocol/nips/blob/master/17.md
3. NIP-28:
   - https://github.com/nostr-protocol/nips/blob/master/28.md
4. NIP-29:
   - https://github.com/nostr-protocol/nips/blob/master/29.md
5. NIP-44:
   - https://github.com/nostr-protocol/nips/blob/master/44.md
6. NIP-59:
   - https://github.com/nostr-protocol/nips/blob/master/59.md
7. NIP-72:
   - https://github.com/nostr-protocol/nips/blob/master/72.md
