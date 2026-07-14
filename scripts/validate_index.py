#!/usr/bin/env python3
"""Validate the Capa registry index and its signatures.

This is the registry's CI safety net. It fails (non-zero exit) when a
curator's hand-edit + hand-sign of ``index.json`` would ship something
the Capa toolchain would reject, or a signature that no longer matches
the index bytes, or a ``latest`` tag that does not exist or is signed by
the wrong key. Run on every push / pull request so a broken or unsigned
index can never land unnoticed.

It performs four families of checks:

  1. Schema     - ``index.json`` parses; ``registry_version`` is a
                  supported integer; ``packages`` is an object; each
                  entry has the required fields with correct types; each
                  package name matches the toolchain's accepted name
                  shape; each ``verify_key`` (where present) is a 40-char
                  hex GPG fingerprint; each ``latest`` looks like a tag.
  2. Git URL    - every ``git`` passes the compiler's OWN
                  ``_validate_git_url`` allow-list.
  3. Index sig  - ``index.json.asc`` is a valid detached signature of the
                  CURRENT ``index.json`` bytes, made by the root
                  fingerprint.
  4. Tag sig    - for every package that declares a ``verify_key``, the
                  ``latest`` tag exists in the target git repo and its tag
                  object is GPG-signed by that ``verify_key``.

The trust-critical logic lives in ``scripts/_registry_lib.py`` and is
shared with the local curator tools; this file is just the CI driver.
Install capa from its git tag first so the toolchain rules can be reused::

    pip install git+https://github.com/nelsonduarte/capa-language.git@v1.16.0

Pure stdlib otherwise. GPG verification runs against an ISOLATED keyring
built solely from the public keys committed under ``keys/`` (never the
ambient keyring), so a green run proves the committed key verifies the
signatures - nothing else does. This validator uses PUBLIC keys only and
is safe to run in CI.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path
from typing import Optional

import _registry_lib as lib


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
        "--skip-network", action="store_true",
        help="skip the tag existence + signature checks (offline schema "
             "and index-signature validation only)",
    )
    args = parser.parse_args(argv)

    try:
        lib.assert_root_key_consistency()
    except lib.ValidationError as e:
        sys.stderr.write(f"FATAL: {e}\n")
        return 2

    ok: list[str] = []
    try:
        packages, notes = lib.check_schema(args.index)
        ok += notes
        ok += lib.check_git_urls(packages)

        with tempfile.TemporaryDirectory(prefix="capa_regkeyring_") as kd:
            gnupghome = Path(kd)
            ok += lib.build_keyring(gnupghome, args.keys_dir)
            ok += lib.check_index_signature(args.index, args.sig, gnupghome)
            if args.skip_network:
                ok.append("tag checks SKIPPED (--skip-network)")
            else:
                ok += lib.check_tag_signatures(packages, gnupghome)
    except lib.ValidationError as e:
        for line in ok:
            print(f"ok   {line}")
        print(f"\nFAIL {e}", file=sys.stderr)
        return 1

    for line in ok:
        print(f"ok   {line}")
    print("\nPASS: registry index is valid, signed, and consistent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
