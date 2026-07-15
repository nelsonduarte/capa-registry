<!--
Proposing a package for the curated Capa registry.
See CONTRIBUTING.md for the full flow. The registry is CURATED: only
the root key can sign the index, so a maintainer re-signs your entry
in on merge. You cannot sign it yourself.
-->

## Package

- **Name:** `capa_...`
- **Git URL:** `https://github.com/<owner>/<repo>`
- **verify_key (40-char GPG fingerprint):** ``
- **latest tag:** `vX.Y.Z`
- **Description (one line):**

## Checklist

- [ ] I added one `packages.<name>` entry to `index.json` with the
      required `git` and `verify_key` fields (and, optionally, `latest`
      and `description`).
- [ ] The `latest` tag **exists** in the repo and is **GPG-signed by
      the `verify_key`** above (the key `capa add` verifies against on
      install).
- [ ] The git URL uses an allow-listed transport (public `https://`
      git repository).
- [ ] This is a real Capa library with a stable `pub` surface.
- [ ] CI (schema, git-URL allow-list, tag signature) is green.

<!--
Note: the "index signature" CI check will be RED on this PR, and that
is expected. Editing index.json invalidates the committed signature,
and only the root key can re-sign. A curator re-signs and pushes
index.json + index.json.asc on merge, which turns that check green.
-->
