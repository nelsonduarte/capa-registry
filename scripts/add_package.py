#!/usr/bin/env python3
"""Add or update a ``packages.<name>`` entry (LOCAL curator tool).

Resolves everything the entry needs and writes it in the file's exact
canonical format, then re-signs in one safe step:

  * validates the package NAME shape and the ``git`` URL via capa's own
    validators (refuses on failure);
  * resolves the newest ``vX.Y.Z`` tag in the repo that is GPG-signed by
    the verify key (``--verify-key`` defaults to the registry root key;
    it is required to verify the tag, so an unsigned repo is refused);
  * fills in ``description`` from, in order: ``--description``, the
    existing entry's description (when updating), then the package's own
    ``capa.toml`` ``[package].description`` at that tag; if none can be
    found it refuses and asks for ``--description``;
  * inserts / updates ``packages.<name>`` and re-signs in one safe step -
    which re-verifies EVERY entry's tag signature before signing, so it
    can never produce a signed-but-CI-red index.

``--dry-run`` prints the entry it would add/update and writes nothing.

The ``updated`` top-level date is left UNTOUCHED unless ``--updated
YYYY-MM-DD`` is given (no wall clock here to default it).

LOCAL USE ONLY: a real write re-signs, which needs the root PRIVATE key
(6C1D222D491FB88031E041A536CFB426101AA24B) in your local gpg keyring.
Never run in CI (public key only). Shared trust-critical logic lives in
``scripts/_registry_lib.py``. Install capa from its git tag first::

    pip install git+https://github.com/nelsonduarte/capa-language.git@v1.16.0
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Optional

import _registry_lib as lib
from sign_index import sign_and_verify

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def resolve_entry(
    name: str, git: str, verify_key: Optional[str],
    description: Optional[str], existing: Optional[dict], keys_dir: Path,
) -> tuple[dict, list[str]]:
    """Build the canonical entry dict for ``name``. Returns ``(entry, notes)``.

    Raises ``ValidationError`` on any validation failure (bad name, bad
    git URL, bad verify key, no signed tag, or no resolvable description).
    """
    notes: list[str] = []

    # Name + URL shape: reuse the toolchain's validators.
    if not lib._DEP_NAME_RE.match(name):
        raise lib.ValidationError(
            f"{name!r}: package name does not match the accepted name "
            f"shape {lib._DEP_NAME_RE.pattern}"
        )
    lib.validate_git_url(name, git)
    notes.append(f"{name}: name + git URL accepted")

    # Verify key: default to the root key; must be a well-formed fpr.
    key = verify_key if verify_key else lib.ROOT_FINGERPRINT
    if not lib.is_valid_fingerprint(key):
        raise lib.ValidationError(
            f"{name!r}: --verify-key must be a 40-character hex GPG "
            f"fingerprint, got {key!r}"
        )
    expected = lib.normalise_fingerprint(key)

    with tempfile.TemporaryDirectory(prefix="capa_regkeyring_") as kd:
        gnupghome = Path(kd)
        notes += lib.build_keyring(gnupghome, keys_dir)
        env = lib.gpg_env(gnupghome)

        latest = lib.newest_signed_tag(git, expected, env)
        if latest is None:
            raise lib.ValidationError(
                f"{name!r}: no vX.Y.Z tag in {git} is signed by {expected}; "
                f"a signed tag is required (pass a different --verify-key or "
                f"publish a signed tag)"
            )
        notes.append(f"{name}: newest signed tag is {latest}")

        # Description resolution: flag, then existing entry, then capa.toml.
        desc = description
        source = "--description"
        if desc is None and existing is not None:
            ed = existing.get("description")
            if isinstance(ed, str) and ed:
                desc, source = ed, "existing entry"
        if desc is None:
            fetched = lib.read_capa_toml_description(git, latest, env)
            if fetched:
                desc, source = fetched, "capa.toml"
    if desc is None:
        raise lib.ValidationError(
            f"{name!r}: no description given and none found in the package's "
            f"capa.toml at {latest}; pass --description \"...\""
        )
    notes.append(f"{name}: description from {source}")

    entry = {
        "git": git,
        "verify_key": expected,
        "latest": latest,
        "description": desc,
    }
    return entry, notes


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", help="package name")
    parser.add_argument("git", help="git URL")
    parser.add_argument(
        "--verify-key", metavar="FPR",
        help="40-char GPG fingerprint the tags are signed with "
             "(default: the registry root key)",
    )
    parser.add_argument(
        "--description", help="one-line description (else read from the "
        "existing entry or the package's capa.toml)",
    )
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
        help="print the entry it would add/update and write nothing",
    )
    args = parser.parse_args(argv)

    if args.updated is not None and not _DATE_RE.match(args.updated):
        sys.stderr.write("FATAL: --updated must be YYYY-MM-DD\n")
        return 2

    try:
        lib.assert_root_key_consistency()
        _raw, index = lib.load_index(args.index)
        packages, _notes = lib.validate_index_dict(index)
        existing = packages.get(args.name)
        if existing is not None and not isinstance(existing, dict):
            existing = None
        entry, notes = resolve_entry(
            args.name, args.git, args.verify_key, args.description,
            existing, args.keys_dir,
        )
    except lib.ValidationError as e:
        print(f"\nFAIL {e}", file=sys.stderr)
        return 1

    for line in notes:
        print(f"ok   {line}")

    verb = "update" if args.name in packages else "add"
    print(f"\nwould {verb} packages.{args.name}:")
    print(json.dumps({args.name: entry}, indent=2, ensure_ascii=False))

    if args.dry_run:
        print("\nPASS: --dry-run, wrote nothing")
        return 0

    try:
        index.setdefault("packages", {})[args.name] = entry
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
    print(f"\nPASS: {verb}ed packages.{args.name} and re-signed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
