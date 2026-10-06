# Portable derivative note

This is a protocol reference, not a ready-to-use authorization or signed configuration.
Use the package-root README for the independently runnable TEST_ONLY sample.
Every `<resolved-...>` value is a placeholder: a trusted initializer must derive a canonical absolute path from its current package location, explicit arguments, or environment, then produce and review new hashes and signatures.
No historical grant or acceptance is included. The CLI does not expand placeholders or sign grants.

# TEST_ONLY request-file CLI

This candidate provides a local request-file entry for the current `Controller`:
signed grants, patches, creates, fixed TEST/BUILD commands, candidate freezes,
externally signed author attestations, and internal parent returns. It reads
operation status without opening a writable Controller. With a stronger
bootstrap, it also records a signed CEO acceptance, evaluates PRE_RELEASE,
consumes a separate TEST_ONLY release lease, checks POST_RELEASE read-only,
and can record one verified POST event. The
CEO owns the native Codex invocation, actor mapping, independent review, and
acceptance evidence.

Run from this independent project with Python 3.11+ and its declared dependency
installed. For a source checkout, set `PYTHONPATH` to this project's `src`
directory in the invoking process. No global Codex configuration is needed.

## Trusted bootstrap

An installer or trusted controller prepares a JSON config and records its SHA256
outside request material. All paths are absolute and canonical. The state path
must be outside the workspace; the public pin must be outside the workspace.
The root pin itself is a separate `M2_CONSTRUCTION_PIN_1` JSON file with
`trust_domain=TEST_ONLY`. Its exact-byte SHA256 is in the config. The CLI never
creates a signing key and never signs a grant.

```json
{
  "schema": "M2_CONSTRUCTION_CLI_CONFIG_1",
  "workspace_root": "<resolved-workspace-root>",
  "state_root": "<resolved-state-root>",
  "pin_path": "<resolved-trusted-inputs-root>/public-pin.json",
  "expected_pin_sha256": "<64 lowercase hex characters>"
}
```

The existing `M2_CONSTRUCTION_CLI_CONFIG_1` remains valid for its original
commands and `attest`. To enable `return`, pin an independent reviewer in a
`M2_CONSTRUCTION_CLI_CONFIG_2` config. The reviewer pin is a canonical
`M2_CONSTRUCTION_REVIEWER_PIN_1` TEST_ONLY JSON file with the same four public
fields as the root pin. Its path is absolute, outside the workspace and state
directory, and distinct from the root pin. The CLI verifies its exact-byte
hash before opening a writable Controller. The request cannot choose or
override either public pin.

```json
{
  "schema": "M2_CONSTRUCTION_CLI_CONFIG_2",
  "workspace_root": "<resolved-workspace-root>",
  "state_root": "<resolved-state-root>",
  "pin_path": "<resolved-trusted-inputs-root>/root-pin.json",
  "expected_pin_sha256": "<64 lowercase hex characters>",
  "reviewer_pin_path": "<resolved-trusted-inputs-root>/reviewer-pin.json",
  "expected_reviewer_pin_sha256": "<64 lowercase hex characters>"
}
```

For CEO acceptance and release commands, use `M2_CONSTRUCTION_CLI_CONFIG_3`.
It extends config version 2 with a separately pinned child reviewer and CEO
identity. All four pin paths are absolute, canonical, distinct, and outside
both the workspace and state directory. Each expected SHA256 identifies the
exact bytes of its public pin file. The CEO pin has schema
`M2_CONSTRUCTION_CEO_PIN_1`; both reviewer pins have schema
`M2_CONSTRUCTION_REVIEWER_PIN_1`. All use `trust_domain=TEST_ONLY`. Version 1
and 2 configs remain valid for their earlier commands; the five release-stage
commands require version 3. `return` also accepts version 3: it verifies the
child review with `child_reviewer_pin_path`, while version 2 uses its single
`reviewer_pin_path`. The version 3 parent reviewer pin remains for the parent
review in CEO acceptance and pre-release checks.

```json
{
  "schema": "M2_CONSTRUCTION_CLI_CONFIG_3",
  "workspace_root": "<resolved-workspace-root>",
  "state_root": "<resolved-state-root>",
  "pin_path": "<resolved-trusted-inputs-root>/root-pin.json",
  "expected_pin_sha256": "<exact root pin SHA256>",
  "reviewer_pin_path": "<resolved-trusted-inputs-root>/parent-reviewer-pin.json",
  "expected_reviewer_pin_sha256": "<exact parent reviewer pin SHA256>",
  "child_reviewer_pin_path": "<resolved-trusted-inputs-root>/child-reviewer-pin.json",
  "expected_child_reviewer_pin_sha256": "<exact child reviewer pin SHA256>",
  "ceo_pin_path": "<resolved-trusted-inputs-root>/ceo-pin.json",
  "expected_ceo_pin_sha256": "<exact CEO pin SHA256>"
}
```

Pass the *previously reviewed* exact-byte config SHA256 through
`--config-sha256`. Do not calculate that argument from the request-controlled
config at dispatch time. The request file has no workspace, state, or pin
override. First use of `grant` creates the configured state ledger if absent;
the trusted installation must retain and protect that same ledger through
restart. Config pinning alone does not protect against deletion/replacement of
the ledger by a separately privileged process.

## Requests

`grant` consumes a signed TEST_ONLY envelope issued through the independent
test identity. The envelope is verified by the Controller against the pinned
public key, current time, signed workspace/state identity, scope, and budget.
The CLI does not accept a `verified` claim in its place.

```json
{
  "schema": "M2_CONSTRUCTION_GRANT_REQUEST_1",
  "signed_scope": {
    "schema": "M2_CONSTRUCTION_SIGNED_SCOPE_1",
    "body": {"...": "signed Controller scope fields"},
    "signature_b64": "<signature from the independent TEST_ONLY issuer>"
  }
}
```

Prefer `M2_CONSTRUCTION_PATCH_REQUEST_2` or `CREATE_REQUEST_2` with
`content_b64` for exact candidate bytes. This avoids writing an ungoverned
staging file inside the workspace. The base64 value is strictly decoded and
limited to 14 million encoded characters; it is never echoed in the result.
The earlier `_1` requests remain accepted for compatibility: they read
`content_file` as exact bytes, without text decoding or newline conversion.
That field is a POSIX-style path relative to the configured workspace and must
name an existing ordinary file, without link components or `..`. The target
`path` is separately checked by the signed scope and Controller. A replay with
the same operation ID and the same effective target and bytes returns the prior
result without writing again; changing those operation inputs returns a
conflict. A create target must be absent and listed
under `creatable_files` in the current
signed `M2_CONSTRUCTION_SCOPE_3` grant, with an absent baseline and `CREATE`
effect. It never replaces an existing file.

For new callers, use the inline forms (the shown base64 decodes to `x = 1\n`):

```json
{"schema":"M2_CONSTRUCTION_PATCH_REQUEST_2","grant_id":"grant-01","task_id":"task-01","task_revision":1,"operation_id":"op-01","path":"sample.py","before_sha256":"<current target SHA256>","content_b64":"eCA9IDEK"}
```

```json
{"schema":"M2_CONSTRUCTION_CREATE_REQUEST_2","grant_id":"grant-01","task_id":"task-01","task_revision":1,"operation_id":"create-check","path":"tests/check.py","content_b64":"eCA9IDEK"}
```

The following `_1` forms document the supported file-input compatibility path.

```json
{
  "schema": "M2_CONSTRUCTION_PATCH_REQUEST_1",
  "grant_id": "grant-01",
  "task_id": "task-01",
  "task_revision": 1,
  "operation_id": "op-01",
  "path": "sample.py",
  "before_sha256": "<SHA256 of the target's current bytes>",
  "content_file": "staging/candidate.bin"
}
```

```json
{
  "schema": "M2_CONSTRUCTION_CREATE_REQUEST_1",
  "grant_id": "grant-01",
  "task_id": "task-01",
  "task_revision": 1,
  "operation_id": "create-check",
  "path": "tests/check.py",
  "content_file": "staging/check.py.bin"
}
```

`command` takes only a `command_id`, never an argv or environment from the
request. The current signed grant fixes each TEST/BUILD command's executable,
SHA256, arguments, working directory, environment, time limit, tracked paths,
and BUILD outputs. The Controller checks the stored signature and current task
revision again on every call. A real process receipt is retained under the
configured state directory; only `PASSED` can support a freeze.

```json
{
  "schema": "M2_CONSTRUCTION_COMMAND_REQUEST_1",
  "grant_id": "grant-01",
  "task_id": "task-01",
  "task_revision": 1,
  "operation_id": "build-01",
  "command_id": "build-package"
}
```

Run a signed BUILD command for build outputs and a signed TEST command that
covers the final source, test, and build bytes. `freeze` then uses their actual
operation IDs. Empty `build_files` and `build_operation_ids` arrays are allowed
when there is no build output. With build files, each one needs a passing,
same-task governed BUILD output receipt. A freeze is a candidate snapshot, not
independent approval or release permission.

```json
{
  "schema": "M2_CONSTRUCTION_FREEZE_REQUEST_1",
  "grant_id": "grant-01",
  "task_id": "task-01",
  "task_revision": 1,
  "operation_id": "freeze-01",
  "source_files": ["sample.py"],
  "test_files": ["tests/check.py"],
  "build_files": ["dist/package.bin"],
  "test_operation_ids": ["test-01"],
  "build_operation_ids": ["build-01"]
}
```

`attest` records a Test Root signed authorship envelope for the latest frozen
candidate in the current grant and task revision. The independent issuer must
verify the actual author before signing; the CLI never signs or accepts a
caller-declared `verified` flag. The Controller verifies the signature,
manifest bytes, current scope, and latest freeze. Repeating the same envelope
returns `ATTESTED` with `effect_executed=false`.

```json
{
  "schema": "M2_CONSTRUCTION_ATTEST_REQUEST_1",
  "grant_id": "grant-01",
  "task_id": "task-01",
  "task_revision": 2,
  "manifest_sha256": "<frozen manifest SHA256>",
  "signed_authorship": {
    "schema": "M2_CONSTRUCTION_SIGNED_AUTHORSHIP_1",
    "body": {
      "schema": "M2_CONSTRUCTION_AUTHORSHIP_1",
      "trust_domain": "TEST_ONLY",
      "grant_id": "grant-01",
      "task_id": "task-01",
      "task_revision": 2,
      "candidate_sha256": "<same frozen manifest SHA256>",
      "author_fingerprint": "<actual author public key fingerprint>"
    },
    "signature_b64": "<independent Test Root signature>"
  }
}
```

`return` consumes a separate Test Root signed instruction after a fresh local
GO verdict against the child reviewer pinned by the selected config. Its exact request
fields are `schema`, `signed_return`, and `signed_review`; reviewer paths,
hashes, parent destinations, or authority flags outside the signed envelopes
are rejected. The signed return body contains `return_id`, child and parent
grant/task IDs and revisions, `candidate_sha256`, `review_sha256`, the complete
`files` mapping (`source`, `destination`, `sha256` for each file), and the
`not_before` / `expires_at` interval. The Controller verifies those fields,
current scopes, actual candidate and review evidence, and exact copied bytes.
One return ID is idempotent; a second ID for the same candidate is denied.
This effect is `INTERNAL_PARENT_ONLY` and grants no release permission.
The review body's exact fields are `schema`, `trust_domain`, `grant_id`,
`task_id`, `task_revision`, `candidate_sha256`, `test_receipts`,
`freeze_event_hash`, `author_fingerprint`, `reviewer_fingerprint`, `decision`,
and `reason`.

```json
{
  "schema": "M2_CONSTRUCTION_RETURN_REQUEST_1",
  "signed_return": {
    "schema": "M2_CONSTRUCTION_SIGNED_RETURN_1",
    "body": {
      "schema": "M2_CONSTRUCTION_RETURN_BODY_1",
      "trust_domain": "TEST_ONLY",
      "return_id": "return-01",
      "child_grant_id": "grant-01",
      "child_task_id": "task-01",
      "child_task_revision": 2,
      "parent_grant_id": "parent-grant",
      "parent_task_id": "parent-task",
      "parent_task_revision": 1,
      "candidate_sha256": "<frozen manifest SHA256>",
      "review_sha256": "<SHA256 of the canonical signed_review envelope>",
      "files": [{"source": "src/value.py", "destination": "parent/src/value.py", "sha256": "<source file SHA256>"}],
      "not_before": 0,
      "expires_at": 1
    },
    "signature_b64": "<independent Test Root signature>"
  },
  "signed_review": {
    "schema": "M2_CONSTRUCTION_SIGNED_REVIEW_1",
    "body": {"...": "signed independent GO review fields"},
    "signature_b64": "<independent reviewer signature>"
  }
}
```

The interval above is schematic: supply valid current Unix seconds. All
signatures are over the canonical envelope body. The CLI outputs only selected
status, IDs, hashes, and authority; it does not echo signed envelopes, file
payloads, or key material.

## CEO acceptance and TEST_ONLY release

The five commands below use the exact-byte reviewed config SHA256 from version
3. Request files cannot supply or override any Root, parent reviewer, child
reviewer, or CEO pin path or expected hash. The root signing key and all other
private keys remain outside the CLI. The `signed_ceo_acceptance` envelope must
contain `signed_roles`, a Test Root signed
`M2_CONSTRUCTION_SIGNED_PRE_RELEASE_ROLES_1` proof binding the parent grant,
task, revision, candidate hash, review hash, reviewer fingerprint, and CEO
fingerprint. The acceptance itself is signed by the pinned CEO identity and
binds the consumed child return. A new CEO public key cannot authorize itself.
The outer envelopes have exactly `schema`, `body`, and `signature_b64`.
The acceptance body schema is `M2_CONSTRUCTION_CEO_ACCEPTANCE_BODY_1` and its
exact fields are `schema`, `trust_domain`, `decision`, `ceo_fingerprint`,
`parent_grant_id`, `parent_task_id`, `parent_task_revision`,
`candidate_sha256`, `review_sha256`, `internal_return_operation_id`,
`internal_return_files_sha256`, `internal_return_event_hash`,
`child_grant_id`, `child_task_id`, `child_task_revision`,
`child_candidate_sha256`, `not_before`, `expires_at`, and `signed_roles`.
`decision` must be `ACCEPT` to reach PRE PASS.

`ceo-accept` records one durable `CEO_ACCEPTED` event after checking the parent
and child scopes, reviews, freeze records, actual files, and return provenance.
It returns `ACCEPTED` with `effect_executed=true` on first recording and false
on exact replay. It does not dispatch or copy release files. `pre-release`
requires that recorded event and returns a current `PASS`, `FAIL`, or
`INDETERMINATE` verdict without writing the ledger. Both use the same eight
request fields; only the schema differs. `ceo-accept` requires an existing
trusted ledger and does not create one:

```json
{
  "schema": "M2_CONSTRUCTION_CEO_ACCEPT_REQUEST_1",
  "grant_id": "parent-grant",
  "task_id": "parent-task",
  "task_revision": 1,
  "manifest_path": "<resolved-state-root>/candidates/parent-manifest.json",
  "expected_manifest_sha256": "<frozen parent manifest SHA256>",
  "signed_review": {"...": "pinned parent reviewer signed GO proof"},
  "signed_ceo_acceptance": {"...": "pinned CEO signed acceptance with Test Root signed_roles"}
}
```

For `pre-release`, change only `schema` to
`M2_CONSTRUCTION_PRE_RELEASE_REQUEST_1`. The manifest path identifies the
frozen parent candidate inside the pinned state directory; its hash is
rechecked against the ledger and file bytes. `PASS` includes
`pre_release_sha256` and hashes needed by the separate release issuer. A PASS
has `dispatch_allowed=false` and does not itself grant release permission.

`release` requires a separate Test Root signed
`M2_CONSTRUCTION_SIGNED_RELEASE_1` lease. Its body fixes the release ID, parent
scope, candidate/review/CEO/PRE hashes, returned operation and files hash,
isolated absolute `target_root`, exact source-to-destination file mapping, and
validity interval. Prepare the target root and destination parent directories
outside the workspace and state directory before consumption; this isolated
tree must contain no unlisted files or directories. The Controller
reruns PRE and checks the lease, candidate, and target before copying. Exact
replay of a completed operation returns its historical `COMPLETED` result with
`effect_executed=false`, even after lease expiry, only after rechecking the
signed request, stored receipt, event chain, and entire target tree. This is
a read of the prior effect, not a new release authorization. An uncertain effect
returns `UNKNOWN` and is not automatically repeated. The release body schema is
`M2_CONSTRUCTION_RELEASE_BODY_1` and its exact fields are `schema`,
`trust_domain`, `release_id`, `parent_grant_id`, `parent_task_id`,
`parent_task_revision`, `candidate_sha256`, `review_sha256`,
`ceo_acceptance_sha256`, `pre_release_sha256`, `return_operation_id`,
`return_files_sha256`, `target_root`, `files`, `not_before`, and `expires_at`.
Each `files` entry has exactly `source`, `destination`, and `sha256`. `release`
also requires the existing trusted ledger.

```json
{
  "schema": "M2_CONSTRUCTION_RELEASE_REQUEST_1",
  "signed_release": {"...": "separate Test Root signed exact release lease"},
  "signed_review": {"...": "same parent signed GO review"},
  "signed_ceo_acceptance": {"...": "same signed CEO acceptance"}
}
```

`post-release` reads the ledger and released target bytes again. It requires
only the exact signed release lease and returns `VERIFIED` when the completed
effect, exact target tree, and current bytes match; it performs no new effect.

```json
{
  "schema": "M2_CONSTRUCTION_POST_RELEASE_REQUEST_1",
  "signed_release": {"...": "same signed release lease"}
}
```

`post-verify` uses the same signed lease in a distinct request schema. It
recomputes POST, rechecks the released bytes and ledger head, then records one
`POST_RELEASE_VERIFIED` event in the trusted ledger. Its first successful
result is `VERIFIED` with `effect_executed=true`; exact repeat after a fresh
successful check returns `effect_executed=false`. A prior event is a record of
that moment, not permanent control of the target. If target bytes later
change, `post-verify` denies even when the earlier event remains. This
command requires the existing trusted ledger and does not copy or publish
files.

```json
{
  "schema": "M2_CONSTRUCTION_POST_VERIFY_REQUEST_1",
  "signed_release": {"...": "same signed release lease"}
}
```

Invoke these as `ceo-accept`, `pre-release`, `release`, `post-release`, and
`post-verify` with the usual `--config`, `--config-sha256`, and `--request`
arguments. All
signatures and hashes must be prepared by independent trusted issuers; the CLI
does not sign them. This flow is a local `TEST_ONLY` rehearsal. It does not
establish native Codex actor identity, formal release acceptance, or authority
to publish to a real product environment.

`status` accepts a request with only the schema for event-chain status, or an
additional `operation_id` for one persisted operation. It opens the configured
SQLite file in read-only mode, verifies the event hash chain, and returns its
head and the operation status/hashes. It does not create a missing ledger,
repair a tampered chain, dispatch an effect, or infer that an `UNKNOWN` effect
did or did not happen. It is a snapshot of the stored ledger, not an external
anchor for independently altered database files.

```json
{"schema": "M2_CONSTRUCTION_STATUS_REQUEST_1", "operation_id": "op-01"}
```

From PowerShell, after a trusted party has provisioned the config, pin, signed
scope, and request files:

```powershell
$packageRoot = (Get-Location).Path
$env:PYTHONPATH = (Join-Path $packageRoot "core/src")
# Read these three independently reviewed inputs from the current environment.
$trustedInputs = (Resolve-Path $env:M2_TRUSTED_INPUTS).Path
$configHash = $env:M2_REVIEWED_CONFIG_SHA256
$configHashV2 = $env:M2_REVIEWED_CONFIG_V2_SHA256
$configHashV3 = $env:M2_REVIEWED_CONFIG_V3_SHA256
python -m m2_construction.cli --config (Join-Path $trustedInputs "bootstrap.json") --config-sha256 $configHash grant --request (Join-Path $trustedInputs "grant.json")
python -m m2_construction.cli --config (Join-Path $trustedInputs "bootstrap.json") --config-sha256 $configHash patch --request (Join-Path $trustedInputs "patch.json")
python -m m2_construction.cli --config (Join-Path $trustedInputs "bootstrap.json") --config-sha256 $configHash create --request (Join-Path $trustedInputs "create.json")
python -m m2_construction.cli --config (Join-Path $trustedInputs "bootstrap.json") --config-sha256 $configHash command --request (Join-Path $trustedInputs "build.json")
python -m m2_construction.cli --config (Join-Path $trustedInputs "bootstrap.json") --config-sha256 $configHash command --request (Join-Path $trustedInputs "test.json")
python -m m2_construction.cli --config (Join-Path $trustedInputs "bootstrap.json") --config-sha256 $configHash freeze --request (Join-Path $trustedInputs "freeze.json")
python -m m2_construction.cli --config (Join-Path $trustedInputs "bootstrap-v2.json") --config-sha256 $configHashV2 attest --request (Join-Path $trustedInputs "attest.json")
python -m m2_construction.cli --config (Join-Path $trustedInputs "bootstrap-v2.json") --config-sha256 $configHashV2 return --request (Join-Path $trustedInputs "return.json")
python -m m2_construction.cli --config (Join-Path $trustedInputs "bootstrap-v3.json") --config-sha256 $configHashV3 ceo-accept --request (Join-Path $trustedInputs "ceo-accept.json")
python -m m2_construction.cli --config (Join-Path $trustedInputs "bootstrap-v3.json") --config-sha256 $configHashV3 pre-release --request (Join-Path $trustedInputs "pre-release.json")
python -m m2_construction.cli --config (Join-Path $trustedInputs "bootstrap-v3.json") --config-sha256 $configHashV3 release --request (Join-Path $trustedInputs "release.json")
python -m m2_construction.cli --config (Join-Path $trustedInputs "bootstrap-v3.json") --config-sha256 $configHashV3 post-release --request (Join-Path $trustedInputs "post-release.json")
python -m m2_construction.cli --config (Join-Path $trustedInputs "bootstrap-v3.json") --config-sha256 $configHashV3 post-verify --request (Join-Path $trustedInputs "post-verify.json")
python -m m2_construction.cli --config (Join-Path $trustedInputs "bootstrap.json") --config-sha256 $configHash status --request (Join-Path $trustedInputs "status.json")
```

Each invocation emits one JSON object on stdout. `GRANTED`, `COMPLETED`,
`PASSED`, `FROZEN`, `ATTESTED`, `ACCEPTED`, `PASS`, `VERIFIED`, and `OK` exit 0;
denials, `FAIL`, conflicts, and failed command statuses exit 2; `UNKNOWN` and
`INDETERMINATE` exit 3. A new `UNKNOWN` may follow an uncertain
post-intent effect; replaying its operation ID does not dispatch it again.
Results contain status, reason codes, IDs, hashes, and paths to Controller
receipts or the candidate manifest, never payload bytes, signatures, or private
keys. Requests cannot override the config's workspace, state, or public pin paths.
Keep signed request files, and any `_1` staging files, under appropriate local permissions. The
CLI is an entry gate; it does not claim an OS sandbox or control other native
host tools. A real Codex call, its native tool ID, and any test/build/return
mapping require separate evidence.

### Candidate R4: host-controlled file evidence for memory projection

`EvidenceProjection(controller, orchestration, memory, read_file_evidence=reader)`
optionally installs a **trusted host** reader. Ordinary `project_memory` and
`load_projection` requests cannot supply visible file names or verification flags.
Without this reader, prior event-only visibility and exclusions remain in force.

`reader(binding, source)` must enforce the host's existing current read policy,
task/source provenance, approved roots, exact file allowlist, and link/escape
checks before reading actual bytes. It must return exactly:

```python
{
    "binding": actual_current_binding,  # complete seven-field native binding
    "source": actual_source_descriptor,
    "ref": actual_relative_reference,
    "content": actual_file_bytes,       # bytes, not a claimed digest/verified flag
    "read_policy_sha256": current_host_read_policy_digest,
}
```

Install this callable in reviewed host code, never from agent arguments or author
documents. On lost permission or missing evidence it must raise; on any permission
policy change its policy digest must change. A malicious host callback can lie
about permission: this interface is a trust boundary, not an OS sandbox, new trust
root, or cryptographic proof of filesystem permissions.

The projection verifies binding types/values, the exact registered source and
version, and SHA256 of the returned bytes. This adapter supports one file per
source, with `source.sha256` equal to that file's byte hash. It does not invent a
hash mapping for multi-file manifests or opaque references. Verification and
activation still use MemoryStore's independent trusted proof checks; the reader
does not promote entries, replace signatures, or grant execution authority.

`file_evidence` records these checked source/file/policy commitments separately
from Ledger event IDs. Project creation rereads them; cached loads require the
reader again, match current memory sources, and reread the same bytes/policy.
Current advisory manifests remain required at load. Revocation, version, binding,
scope, lease and expiry rules stay in force. Missing files, wrong hashes, changed
policies or unavailable readers deny instead of serving the old adopted skill.
Head vectors alone do not establish file currentness; call `load_projection`.

Migration is controlled: do not expose caches containing file-backed adoptions to
old readers that do not implement this revalidation. Use an isolated candidate
state; before rollback, the owner must retire/rebuild affected derived projection
rows under an approved procedure. This candidate does not mutate old caches,
publish a host integration, or claim context/supervisor/experimental acceptance.

### Candidate R5: file-backed advisory consumption in context

`context_bundle(..., capture_sources=..., read_current=...,
read_projection_current=None, now=None)` preserves event-only callers. When the
captured projection has file commitments, the additional trusted host callback
is required. Its signature is `(projection_hash, task_binding)`; it must return
the actual result of `service.load_projection(projection_hash, task_binding,
read_advisory_current=current_advisory_reader)` on the service configured with
the approved file reader above. Do not return a saved object, `current_heads`,
or a caller-provided `verified` flag. Missing currentness evidence returns
`INCOMPLETE / FILE_EVIDENCE_CURRENTNESS_REQUIRED`.

Context checks the commitment shape, full binding, source identity/version/hash,
canonical relative reference and permission digest, then compares a current
projection load with the exact captured projection before and after assembly.
Reader failures propagate; source/binding/policy/expiry/revocation changes must
be rejected by that actual load. These are trusted host entry points, not model
arguments. A malicious host can lie; two reads are not an atomic filesystem
snapshot, and the capsule does not authorize future effects.

File-backed `advisory_memory` entries carry a separate `file_evidence` list:
each item has `type=FILE_EVIDENCE_1` plus binding, source, ref, content_sha256 and
read_policy_sha256. Match the complete source and reference, not only a path.
The ordinary `evidence_refs` field continues to contain only event evidence IDs;
file paths are never promoted to Ledger facts or visible event IDs. Each entry
and its file commitments fit the budget together or appear in `omitted_items`
as `BUDGET_LIMIT`. Required hard constraints and UNKNOWN remain intact, and
`dispatch_allowed` remains false. Host/supervisor wiring and formal experiments
remain outside this candidate's local acceptance.
