#!/usr/bin/env python3
"""Re-sign ``index.json`` in one safe step (LOCAL curator tool).

Replaces the manual ``gpg --armor --detach-sign ...`` incantation and
its footguns. It:

  1. runs the schema + git-URL checks and REFUSES to sign a structurally
     invalid index (so you never wrap a signature around a broken file);
  2. produces ``index.json.asc``, a detached signature over the EXACT
     current ``index.json`` bytes, made by the registry root key; then
  3. re-reads and VERIFIES the fresh signature against an isolated
     keyring built from ``keys/`` and prints confirmation.

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
) -> list[str]:
    """Schema/URL-check, sign, then verify the fresh signature.

    Shared by this tool and by ``refresh_latest`` / ``add_package`` after
    they mutate the index, so every write path re-signs the same safe way.
    """
    _raw, index = lib.load_index(index_path)
    packages, notes = lib.validate_index_dict(index)
    notes += lib.check_git_urls(packages)

    lib.sign_index(index_path, sig_path)
    notes.append(f"signed {index_path.name} -> {sig_path.name}")

    with tempfile.TemporaryDirectory(prefix="capa_regkeyring_") as kd:
        gnupghome = Path(kd)
        notes += lib.build_keyring(gnupghome, keys_dir)
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
    args = parser.parse_args(argv)

    try:
        lib.assert_root_key_consistency()
        notes = sign_and_verify(args.index, args.sig, args.keys_dir)
    except lib.ValidationError as e:
        print(f"\nFAIL {e}", file=sys.stderr)
        return 1

    for line in notes:
        print(f"ok   {line}")
    print("\nPASS: index re-signed and the fresh signature verifies")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
