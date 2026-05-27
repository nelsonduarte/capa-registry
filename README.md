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
      "verify_key": "<40-char GPG fingerprint, optional>",
      "latest": "<latest released tag, e.g. v0.1.3>",
      "description": "<one line>"
    }
  }
}
```

- `git` is required. `verify_key`, `latest`, and `description`
  are optional; a package with no `verify_key` is installed
  without GPG-tag verification (the consumer can still add one
  in their own `capa.toml`).
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

The index is a name-to-URL convenience, not a trust root by
itself. The actual integrity guarantees come from the same
three layers `capa install` already enforces:

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
signed by the real key.

## Adding a package

Open a pull request that adds a `packages.<name>` entry. The
package must:

- Be public and buildable by the current Capa release candidate.
- Ship signed tags (recommended) and a SLSA L2 release workflow
  (recommended) so the three-layer trust model applies.
- Have a stable public API surface (a `pub` boundary that the
  importing program can rely on).

## License

Apache-2.0. See [LICENSE](LICENSE).
