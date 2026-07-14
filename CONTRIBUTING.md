# Contributing a package to capa-registry

This is the **process** guide for getting a package listed. For the
raw entry schema and the trust model, see the
[README](README.md) (the "Adding a package", "Format", and "Trust
model" sections); this document does not repeat them.

## What the registry is

`capa-registry` is a **curated**, GPG-signed name index for the Capa
package manager. It maps a short package name to a git URL, the GPG
fingerprint the package's tags are signed with, and the latest
released tag, so that

```
capa add capa_http
```

resolves to the full `--git ... --tag ... --verify-key ...` install.

The word **curated** is load-bearing. The whole index ships with a
single detached signature `index.json.asc` produced by **one** key,
the registry root key
(`6C1D 222D 491F B880 31E0 41A5 36CF B426 101A A24B`). The Capa
toolchain verifies the index bytes against that fingerprint, which is
baked into the toolchain binary, before it trusts any entry. Because
there is exactly one signer, **inclusion is by review**: a maintainer
reviews the package and re-signs the index. **Third-party
self-service publishing is not available yet.** You cannot sign the
index, so you cannot land an entry on your own; you propose it, and
the curator signs it in on merge.

`capa add --git <url> ...` installs any package directly from its git
repo and does not pass through this index, so you never need to be
listed here to be usable. The registry is a convenience and a curated
trust root, not a gate on the ecosystem.

## How to propose a package

Open a pull request that adds one `packages.<name>` entry to
[`index.json`](index.json), following the shape documented in the
README "Adding a package" section:

```json
"capa_example": {
  "git": "https://github.com/<owner>/<repo>",
  "verify_key": "<40-char GPG fingerprint your tags are signed with>",
  "latest": "v0.1.0",
  "description": "<one line>"
}
```

- `git` is the package's repository URL.
- `verify_key` is the GPG fingerprint your release tags are signed
  with. Include it: without it the package is installed with no
  tag-signature verification.
- `latest` is a released tag of the form `vX.Y.Z`.
- `description` is a single line.

Fill in the [pull request template](.github/PULL_REQUEST_TEMPLATE.md)
so the curator has the name, URL, fingerprint, tag, and a
confirmation that the tag is signed.

## Requirements you must meet

These are the properties the curator and the CI check for, and the
reason each one matters:

1. **The git URL uses an allow-listed transport.** The registry
   validator runs your `git` URL through the compiler's own
   `_validate_git_url` allow-list (the same one `capa add` enforces),
   so an entry that Capa itself would refuse to clone never lands.

2. **The `latest` tag exists and is GPG-signed by the declared
   `verify_key`.** This is the core of the trust chain. When someone
   runs `capa add <name>`, the resolved `verify_key` is exactly what
   the install flow checks the tag signature against. If the tag is
   unsigned, signed by a different key, or missing, the listing would
   promise a guarantee the install cannot honor, so the registry
   refuses it. (A package with no `verify_key` at all is allowed, but
   it is then installed with no tag verification; ship a signed tag
   and declare the key if you want the guarantee.)

3. **The package is a real Capa library** with a stable public
   surface (a `pub` boundary an importing program can rely on), as
   described in the README. The registry lists usable libraries, not
   placeholders.

## What CI checks automatically on your PR

Every push and pull request runs
[`scripts/validate_index.py`](scripts/validate_index.py) via the
[`validate` workflow](.github/workflows/validate.yml). It builds an
isolated GPG keyring from the **public** keys committed under `keys/`
(never the runner's ambient keyring) and runs four families of
checks:

1. **Schema.** `index.json` parses; `registry_version` is a supported
   integer; every package name matches Capa's accepted name shape;
   `git` is present; `verify_key` (where present) is a 40-character
   hex fingerprint; `latest` looks like a `vX.Y.Z` tag and is a
   git-argv-safe ref; no unknown fields (a typo like `latset` is
   rejected rather than silently dropped).
2. **Git URL allow-list.** Every `git` URL passes the compiler's own
   `_validate_git_url`.
3. **Index signature.** `index.json.asc` is a valid detached
   signature over the **current** `index.json` bytes, by the root
   fingerprint.
4. **Tag signature.** For every package that declares a `verify_key`,
   the `latest` tag exists in the target repo and its tag object is
   GPG-signed by that key.

Checks 1, 2, and 4 give you fast, direct feedback on your proposed
entry: a bad URL, a missing or unsigned tag, or a malformed field
turns the job red with the exact reason.

**Expect check 3 (index signature) to be red on your PR, and that is
normal.** Editing `index.json` changes its bytes, so the committed
`index.json.asc` no longer matches, and only the root key can produce
a fresh signature. You cannot re-sign, so the signature check stays
red until the curator re-signs on merge. Treat checks 1, 2, and 4 as
the ones you drive to green; check 3 is the curator's step.

## What the curator does to accept

Only the root key can sign the index, and it is held **locally** by
the curator, never in CI (the workflow has the public key only and
can never sign). On accepting a proposal the curator, on their local
machine with the root private key in their gpg keyring, either:

- runs [`scripts/add_package.py`](scripts/add_package.py), e.g.

  ```
  python scripts/add_package.py <name> <git-url>
  ```

  which validates the name and URL, resolves the newest `vX.Y.Z` tag
  in the repo that is signed by the verify key (defaulting to the
  root key; pass `--verify-key <fpr>` for a different signer),
  fills in the description, inserts the entry in canonical form, and
  **re-signs the index in one step** (re-verifying every entry's tag
  signature first, so it can never produce a signed-but-CI-red
  index); or

- edits `index.json` by hand and then runs
  [`scripts/sign_index.py`](scripts/sign_index.py), which
  schema-checks the file, verifies every entry's `latest` tag
  signature, produces `index.json.asc` over the exact current bytes,
  and re-reads and verifies that fresh signature.

The curator then pushes the updated `index.json` **and**
`index.json.asc` together. That push turns all four CI checks green,
including the index-signature check that was red on your proposal.

To be explicit about the trust boundary: **the contributor cannot
sign the index.** The signature is what makes an entry trusted, and
it can only be applied by the root key, which lives with the curator.
Your PR proposes the entry; the curator's re-sign on merge is what
admits it.
