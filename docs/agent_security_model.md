# Agent Security Model

What the SeedPass session agent protects, what it does not, and why. Written
so a reviewer does not have to infer the intended boundary from the code.

Scope: `js/packages/cli/src/agent.ts` and the token surface it serves. The
vault formats and derivations are covered by
`docs/typescript_port_compatibility_matrix.md`.

## The problem

A stateless CLI must hold an unlocked seed somewhere to be usable, and an AI
agent or automation that drives it should be able to *use* a credential
without being handed the vault. Those are two different principals sharing
one machine.

## Principals

| Principal | Proves itself with | Gets |
|---|---|---|
| Owner | The capability secret in a `0600` file beside the socket | Everything: unlock/lock, the parent seed, token issuance, status, shutdown |
| Token holder | A bearer token issued by the owner | Only what the token's scopes and constraints allow, enforced by the daemon |
| Anyone else | Nothing | Nothing but a liveness ping |

Enforcement lives in the daemon, never in the CLI. The CLI is untrusted from
the daemon's point of view: any local process can speak the socket protocol,
so a check that exists only in the client is not a check at all. (This was a
real defect, found in review: the socket accepted privileged operations from
any local process because the restrictions lived in the CLI.)

## What the capability does and does not do

The socket is `0600`, which proves only "a process running as this user".
That does not distinguish the owner's CLI from a scoped agent that was
handed a token — both run as you. The capability file raises the bar to "can
read the owner's files", which is the same bar as the vault itself.

**It does not defend against a same-uid attacker.** Anyone who can read that
file, read the vault, or `ptrace` the daemon has already won. Defending
against that needs an OS-level boundary (a separate user, a container, a
hardware token) that a user-space daemon cannot provide. If your threat
model includes hostile code running as you, this design does not save you.

## Token scopes

- `read` — redacted entry metadata only. The daemon filters to entries the
  token's kind and label constraints cover, so out-of-scope entries are not
  disclosed at all, and secret-bearing fields are replaced with `has_*`
  flags. A read token never receives the decrypted index.
- `use` — the daemon delivers a secret to a sink (clipboard, a child
  process's environment, a child's stdin) and returns a receipt. The
  plaintext does not cross the socket back to the holder.
- `reveal` — plaintext egress. Distinct from `use` on purpose.

Constraints: entry kinds, a label regex, a TTL, a use count, and an optional
exec allowlist. Denials do not consume uses. Tokens die with a `vault lock`,
a TTL expiry, or a revoke, and do not come back on the next unlock.

### The honest limit of `use`

A `use` holder that chooses the sink command can read the secret from inside
that command. `--exec 'sh -c "cat > /tmp/stolen"'` is a legitimate use as
far as the daemon is concerned.

So `use` is not "can act without learning". It is:

- **containment**, when the token carries an exec allowlist — then the
  holder can only hand the secret to commands you named;
- **accountability**, always — the audit log records the exact argv that
  received each secret.

If you need a hard guarantee that an agent cannot learn a credential, do not
hand it a `use` token for that credential. Have it call something that holds
the credential itself.

## Audit log

Append-only, HMAC-chained (`sig = HMAC(key_index, prev_sig || canonical
payload)`), keyed by the profile's index key, so only the seed holder can
extend or verify it. A signed head file records the expected record count
and last signature — without it, deleting the log or a suffix of it leaves a
shorter file that still verifies perfectly. `agent audit-verify` walks the chain and fails at the
first break. Writes are serialized so concurrent requests cannot interleave
and desynchronize it. Recorded: unlocks, token lifecycle, index reads,
deliveries (with the sink and argv), and every denial with its reason.
Secret values are never recorded.

## Known limits, stated rather than hidden

1. **Same-uid attackers win** — see above. Concretely: a scoped agent is
   given the app directory, so the capability is deliberately stored
   *outside* it (in `XDG_RUNTIME_DIR`), but a token holder that can read that
   file can still unset its token and act as the owner. Treat a token as a
   convenience and an audit trail, not as a sandbox. Real containment needs a
   separate uid or a container.
2. **`use` can be turned into `reveal`** by a holder that picks the command,
   unless an exec allowlist is set.
3. **Memory is not scrubbed.** Seeds live in the daemon's heap while
   unlocked; JavaScript gives no reliable zeroization. Lock when you are
   done — that drops the seed, its tokens, and the derived audit key.
4. **The capability file lives on disk** for the daemon's lifetime, so it
   survives a crash of the CLI but also a crash of the daemon; a stale file
   is replaced on the next start.
5. **Two protocol-level issues are shared with the Python implementation**
   and cannot be fixed in one implementation without breaking convergence:
   tombstone retention allows deletion replay once the cap is exceeded, and
   SSH and PGP entries at the same index derive the same Ed25519 key. Both
   need a versioned change in both implementations; both are tracked in the
   compatibility matrix.

## Verifying these claims

`js/packages/cli/test/agentSecurity.test.ts` speaks the wire protocol
directly, bypassing the CLI, and asserts: no seed retrieval, token minting,
lock, shutdown, status or seed injection without the capability; no
decrypted index for a read token; no plaintext for a use token; no owner ops
via a token; no `SEEDPASS_*` inheritance in a sink child; correct rejection
of non-string credentials; and that tokens do not survive a lock.

If you change the daemon, add the attack to that file first and watch it
fail before you make it pass.
