# Väktaren audit witness: how to verify

This repository is an append-only, off-box copy of the Väktaren audit anchors.
An automated job on the Väktaren host writes to it once a night, after that
night's root is signed and pending timestamp receipts are upgraded. A
repository ruleset blocks force pushes and branch deletion, so history here
can only grow. Nothing in this repository is ever modified after it is
committed: a newer version of a receipt is a new file.

## Contents

* `pubkey/audit_signing_pubkey.txt`: the Ed25519 public key (raw 32 bytes,
  hex) that signs the roots: `d1eba9c2b1d75e56d4627770448dd8f9c0f90ffaf51e2cae68c9ce9b7b82b093`
  (sha256 of the raw key bytes: `60c67dd0cfd97701909d671f43754e53b3f1e41b10f812244773f2044533ed55`).
* `roots/<date>_<table>_<id>.json`: one per Merkle root, with `id`,
  `source_table`, `root_hex`, `entry_count`, `created_at` (UTC),
  `signature_ed25519_hex` and `public_key_fingerprint_sha256`. A root that
  was never signed carries `"signature_ed25519_hex": "unsigned"` and a null
  fingerprint.
* `roots/<date>_<table>_<id>.<sha16>.ots`: OpenTimestamps proof(s) for that
  root. `<sha16>` is the first 16 hex characters of the file's own sha256. A
  receipt first published as *pending* is published again, upgraded, as a new
  file; both remain.
* `events/<date>_<decision_type>_<decision_log_id>.json`: selected audit-log
  entries, exported as they happen: the entry's `content_sha256`, its
  `migration_audit_id` and `migration_audit_timestamp` (UTC). The entry's
  content is never published here; `content_sha256` lets anyone who is later
  shown the entry check it.

## Check a root's signature

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import hashlib, json
pub = bytes.fromhex(open("pubkey/audit_signing_pubkey.txt").read().split()[-1])
r = json.load(open("roots/<file>.json"))
assert r["public_key_fingerprint_sha256"] == hashlib.sha256(pub).hexdigest()
Ed25519PublicKey.from_public_bytes(pub).verify(
    bytes.fromhex(r["signature_ed25519_hex"]), bytes.fromhex(r["root_hex"]))  # raises if invalid
```

The signed message is the 32 raw bytes of `root_hex`.

## Check a receipt

```sh
pip install opentimestamps-client
ots info roots/<file>.ots                    # "File sha256 hash" must equal root_hex
ots verify -d <root_hex> roots/<file>.ots    # needs a Bitcoin node
```

Without a node, `ots info` prints each `BitcoinBlockHeaderAttestation(<height>)`
and the Merkle root that block header must carry; compare it with any block
explorer. The attested time bounds when the root existed.

## What a root commits to

`root_hex` is a Merkle root over the `this_audit_hash` values of the
`entry_count` rows of the `migration_audit` chain that existed when it was
signed, in `id` order:

* leaf = SHA-256(0x00 || raw 32 bytes of this_audit_hash)
* node = SHA-256(0x01 || left || right); an odd last node is duplicated
* output = lowercase hex

Each `this_audit_hash` = SHA-256 of the UTF-8 text
`target_table|target_row_id|target_row_hash|operation|operator|tier_required|previous_hash|timestamp`
(NULL as `\N`, timestamp in UTC as `YYYY-MM-DDTHH:MI:SS.US`), and
`previous_hash` links each row to the one before. For a decision-log entry,
`target_row_hash` binds the entry's `content_sha256`. An event with
`migration_audit_id` N is therefore covered by every root whose
`entry_count` includes row N.
