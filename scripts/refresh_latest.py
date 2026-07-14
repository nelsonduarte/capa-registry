#!/usr/bin/env python3
"""Bump each package's ``latest`` to its newest SIGNED tag (LOCAL tool).

For every package that declares a ``verify_key``, this finds the newest
``vX.Y.Z`` tag in its git repo that is GPG-signed by that key (the
highest semver among the SIGNED tags only, never an unsigned newer tag),
and where that is newer than the recorded ``latest`` it updates the entry
in ``index.json`` (preserving the file's exact canonical format), then
re-signs in one safe step - which re-verifies EVERY entry's tag signature
before signing, so it can never produce a signed-but-CI-red index - and
reports each change as ``pkg: vOLD -> vNEW``.

  * ``--dry-run`` reports the diff and writes NOTHING (no index edit, no
    signing).
  * If nothing changed it says so and touches neither file.

The ``updated`` top-level date is left UNTOUCHED unless you pass
``--updated YYYY-MM-DD`` (there is no wall clock available here, so the
date is never set programmatically).

LOCAL USE ONLY: a real change re-signs, which needs the root PRIVATE key
(6C1D222D491FB88031E041A536CFB426101AA24B) in your local gpg keyring.
Never run in CI (public key only). Shared trust-critical logic lives in
``scripts/_registry_lib.py``. Install capa from its git tag first::

    pip install git+https://github.com/nelsonduarte/capa-language.git@v1.16.0
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path
from typing import Optional

import _registry_lib as lib
from sign_index import sign_and_verify

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def compute_updates(
    packages: dict, keys_dir: Path,
) -> tuple[list[tuple[str, str, str]], list[str]]:
    """Return ``(changes, notes)`` where each change is
    ``(name, old_latest, new_latest)``.

    Only packages with a ``verify_key`` are considered; the newest tag is
    the highest semver that is signed by that key. A package is reported
    as a change only when the newest signed tag is strictly newer than the
    recorded ``latest``.
    """
    changes: list[tuple[str, str, str]] = []
    notes: list[str] = []
    with tempfile.TemporaryDirectory(prefix="capa_regkeyring_") as kd:
        gnupghome = Path(kd)
        notes += lib.build_keyring(gnupghome, keys_dir)
        env = lib.gpg_env(gnupghome)

        for name in sorted(packages):
            spec = packages[name]
            verify_key = spec.get("verify_key")
            git = spec.get("git")
            if not isinstance(verify_key, str) or not verify_key:
                notes.append(f"{name}: no verify_key, skipped")
                continue
            if not isinstance(git, str):
                notes.append(f"{name}: no git URL, skipped")
                continue
            expected = lib.normalise_fingerprint(verify_key)
            newest = lib.newest_signed_tag(git, expected, env)
            if newest is None:
                notes.append(f"{name}: no signed tag found, skipped")
                continue
            current = spec.get("latest")
            cur_key = (
                lib.parse_tag_version(current)
                if isinstance(current, str) else None
            )
            new_key = lib.parse_tag_version(newest)
            if cur_key is None or new_key > cur_key:
                changes.append((name, current if isinstance(current, str)
                                else "(none)", newest))
            else:
                notes.append(f"{name}: {current} is already newest signed")
    return changes, notes


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
        "--updated", metavar="YYYY-MM-DD",
        help="also set the top-level 'updated' date (left untouched if "
             "omitted; there is no wall clock here to default it)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="report the diff and write nothing",
    )
    args = parser.parse_args(argv)

    if args.updated is not None and not _DATE_RE.match(args.updated):
        sys.stderr.write("FATAL: --updated must be YYYY-MM-DD\n")
        return 2

    try:
        lib.assert_root_key_consistency()
        _raw, index = lib.load_index(args.index)
        packages, notes = lib.validate_index_dict(index)
        notes += lib.check_git_urls(packages)
        changes, more = compute_updates(packages, args.keys_dir)
        notes += more
    except lib.ValidationError as e:
        print(f"\nFAIL {e}", file=sys.stderr)
        return 1

    for line in notes:
        print(f"ok   {line}")

    if not changes:
        print("\nPASS: every latest is already the newest signed tag; "
              "nothing written")
        return 0

    print("\nchanges:")
    for name, old, new in changes:
        print(f"  {name}: {old} -> {new}")

    if args.dry_run:
        print("\nPASS: --dry-run, wrote nothing")
        return 0

    try:
        for name, _old, new in changes:
            index["packages"][name]["latest"] = new
        if args.updated is not None:
            index["updated"] = args.updated
        lib.write_index(args.index, index)
        sign_notes = sign_and_verify(
            args.index, args.sig, args.keys_dir, verify_tags=True,
        )
    except lib.ValidationError as e:
        print(f"\nFAIL {e}", file=sys.stderr)
        return 1

    for line in sign_notes:
        print(f"ok   {line}")
    print(f"\nPASS: updated {len(changes)} package(s) and re-signed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
