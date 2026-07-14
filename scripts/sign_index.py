#!/usr/bin/env python3
"""Re-sign ``index.json`` in one safe step (LOCAL curator tool).

Replaces the manual ``gpg --armor --detach-sign ...`` incantation and
its footguns. It:

  1. runs the schema + git-URL checks and REFUSES to sign a structurally
     invalid index (so you never wrap a signature around a broken file);
  2. by default verifies that EVERY entry's ``latest`` tag exists and is
     signed by that entry's ``verify_key`` (the same tag dimension the CI
     validator enforces), so "one safe step" means a fully-valid index -
     never a signed-but-CI-red one. ``--skip-tag-verify`` opts out for a
     legitimate air-gapped / offline re-sign, printing a clear WARNING
     that the CI validator and install-time ``capa add`` re-verification
     remain the backstop;
  3. produces ``index.json.asc``, a detached signature over the EXACT
     current ``index.json`` bytes, made by the registry root key; then
  4. re-reads and VERIFIES the fresh signature against an isolated
     keyring built from ``keys/`` and prints confirmation.

Without ``--skip-tag-verify``, an entry pointing at an unsigned or
wrong-signer tag makes this tool REFUSE (no signature produced).

LOCAL USE ONLY. Signing needs the root PRIVATE key
(6C1D222D491FB88031E041A536CFB426101AA24B) in your local gpg keyring.
This tool must never run in CI, which holds the PUBLIC key only. The
shared trust-critical logic lives in ``scripts/_registry_lib.py``.

Install capa from its git tag first (the git-URL / name / version rules
are reused from the toolchain)::

    pip install git+https://github.com/nelsonduarte/capa-language.git@v1.16.0
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path
from typing import Optional

import _registry_lib as lib


def sign_and_verify(
    index_path: Path, sig_path: Path, keys_dir: Path,
    verify_tags: bool = True,
) -> list[str]:
    """Schema/URL-check, verify tag signatures, sign, then verify the
    fresh signature.

    Shared by this tool and by ``refresh_latest`` / ``add_package`` after
    they mutate the index, so every write path re-signs the same safe way.

    When ``verify_tags`` is True (the default) every entry's ``latest``
    tag is confirmed to exist and be signed by its ``verify_key`` BEFORE
    signing, so a signature is only ever produced over an index the CI
    validator would also accept. If any entry fails, this raises and no
    signature is written. ``verify_tags=False`` skips ONLY that network
    tag check (air-gapped / offline re-sign); the schema, git-URL, and
    fresh-index-signature checks always run.
    """
    _raw, index = lib.load_index(index_path)
    packages, notes = lib.validate_index_dict(index)
    notes += lib.check_git_urls(packages)

    with tempfile.TemporaryDirectory(prefix="capa_regkeyring_") as kd:
        gnupghome = Path(kd)
        notes += lib.build_keyring(gnupghome, keys_dir)
        # Verify tag signatures BEFORE signing so a failure refuses
        # without ever producing a signature over a CI-red index.
        if verify_tags:
            notes += lib.check_tag_signatures(packages, gnupghome)
        else:
            notes.append(
                "tag signatures NOT verified (--skip-tag-verify)"
            )
        lib.sign_index(index_path, sig_path)
        notes.append(f"signed {index_path.name} -> {sig_path.name}")
        notes += lib.check_index_signature(index_path, sig_path, gnupghome)
    return notes


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--index", type=Path, default=lib.DEFAULT_INDEX,
        help="path to index.json (default: repo root)",
    )
    parser.add_argument(
        "--sig", type=Path, default=lib.DEFAULT_SIG,
        help="path to index.json.asc (default: repo root)",
    )
    parser.add_argument(
        "--keys-dir", type=Path, default=lib.DEFAULT_KEYS_DIR,
        help="directory of trusted public keys (default: keys/)",
    )
    parser.add_argument(
        "--skip-tag-verify", action="store_true",
        help="skip verifying every entry's latest tag signature before "
             "signing (air-gapped / offline re-sign only)",
    )
    args = parser.parse_args(argv)

    if args.skip_tag_verify:
        sys.stderr.write(
            "WARNING: --skip-tag-verify: tag signatures were NOT verified "
            "before signing. The signed index may point at an unsigned or "
            "wrong-signer tag. The CI validator (validate_index.py) and "
            "install-time 'capa add' re-verification remain the backstop.\n"
        )

    try:
        lib.assert_root_key_consistency()
        notes = sign_and_verify(
            args.index, args.sig, args.keys_dir,
            verify_tags=not args.skip_tag_verify,
        )
    except lib.ValidationError as e:
        print(f"\nFAIL {e}", file=sys.stderr)
        return 1

    for line in notes:
        print(f"ok   {line}")
    print("\nPASS: index re-signed and the fresh signature verifies")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
