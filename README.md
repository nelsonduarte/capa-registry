# capa-registry

The name index for the [Capa](https://github.com/nelsonduarte/capa-language)
package manager. It maps a short package name to a git URL, the
GPG fingerprint the package's tags are signed with, and the
latest released tag.

This is what lets you write

```
capa add capa_http
```

instead of the fully-explicit

```
capa add capa_http --git https://github.com/nelsonduarte/capa_http --tag v0.1.3 --verify-key 6C1D222D491FB88031E041A536CFB426101AA24B
```

`capa add <name>` (without `--git`) fetches this index, resolves
the name to its git URL + verify key, defaults the pin to the
`latest` tag, and then runs the normal install flow (clone,
SHA-lock, GPG-tag verification, SLSA L2 attestation check). The
explicit-`--git` form still works for packages not in the index
(forks, private mirrors, third-party libraries).

## Format

A single `index.json` at the repo root:

```json
{
  "registry_version": 1,
  "updated": "2026-05-27",
  "packages": {
    "<name>": {
      "git": "https://github.com/<owner>/<repo>",
      "verify_key": "<40-char GPG fingerprint>",
      "latest": "<latest released tag, e.g. v0.1.3>",
      "description": "<one line>"
    }
  }
}
```

- `git` and `verify_key` are required for every real (git-bearing)
  entry: a listing with a git URL but no valid `verify_key` is
  rejected by the schema check and cannot be signed into the index,
  because it would opt out of the tag-signature verification the
  registry promises. `latest` and `description` are optional.
- `registry_version` lets the resolver refuse an index format it
  does not understand.

## Resolution + caching

The Capa toolchain reads the index from
`https://raw.githubusercontent.com/nelsonduarte/capa-registry/main/index.json`
by default. Override with the `CAPA_REGISTRY_URL` environment
variable (useful for a private mirror or a pinned commit). The
toolchain caches the fetched index locally with a short TTL so
repeated `capa add` calls and offline use do not hammer the
network; a stale cache is preferred over a hard failure when the
fetch cannot complete.

## Trust model

The index resolves a name to a git URL **and** the `verify_key`
that anchors the package's tag-signature check, so the index
itself is a trust root: tamper with it in transit and you
control both the source and the key the consumer trusts. To
close that, the index is **signed**.

### Signed index

`index.json` ships with a detached GPG signature
`index.json.asc`, produced by the registry root key:

```
gpg --armor --detach-sign --local-user <ROOT_KEY> index.json
```

Root key fingerprint:

```
6C1D 222D 491F B880 31E0  41A5 36CF B426 101A A24B
```

The Capa toolchain fetches `index.json.asc` alongside the index
and verifies the exact index bytes against this fingerprint
before trusting any entry. The fingerprint ships **with the
toolchain binary**, out of band from the index, so a MITM or a
poisoned cache cannot substitute it. The toolchain also requires
an authenticated transport (`https://`) for the index URL.

Verification is **fail-closed** against the root key baked into
the toolchain (enforced since 2026-06-01): an index with no
signature, with a signature that does not verify, or signed under
the wrong fingerprint is **rejected**, so a tampered index never
reaches the install flow. The only opt-out is the environment
variable `CAPA_REGISTRY_ALLOW_UNSIGNED=1`, which applies **only**
to an unsigned index (air-gapped or self-hosted mirrors that
legitimately serve no `.asc`); it never rescues a signature that
is present but invalid. `capa add --git <url>` goes straight to
the package's git repo and does not pass through the index, so it
is not affected by this gate. See
`docs/design/signed-registry-index.md` in the main repo.

### Per-package layers

Below the index, the three layers `capa install` already
enforces still apply:

1. **Lockfile SHA pinning** (`capa.lock`) catches a retagged
   release.
2. **GPG tag signatures** verified against the `verify_key`
   catch a compromised account that moves a tag to an attacker
   commit.
3. **SLSA L2 build provenance** in Sigstore Rekor (where the
   package's release workflow publishes it) ties the artefact
   to the build that produced it.

The index carries the `verify_key` so that resolving a name
also pins the expected signer; an attacker who edits this index
to point a name at a malicious repo still cannot forge a tag
signed by the real key -- and now cannot forge the index entry
either, because the index is signed.

## Adding a package

Open a pull request that adds a `packages.<name>` entry. The
package must:

- Be public and buildable by the current Capa release candidate.
- Ship signed tags (recommended) and a SLSA L2 release workflow
  (recommended) so the three-layer trust model applies.
- Have a stable public API surface (a `pub` boundary that the
  importing program can rely on).

After editing `index.json`, **re-sign it** so the detached
signature matches the new bytes:

```
gpg --armor --detach-sign --local-user <ROOT_KEY> index.json
```

and commit `index.json` and `index.json.asc` together. A commit
that changes the index without refreshing the signature will be
rejected by toolchains that enforce verification.

## License

Apache-2.0. See [LICENSE](LICENSE).
