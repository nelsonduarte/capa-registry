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

Reuse over mirroring: the git-URL rule, the package-name shape, and the
supported registry version are IMPORTED from the installed ``capa``
toolchain (``capa.pkg._manifest`` / ``capa.pkg._registry``) so this CI
can never drift from what ``capa`` actually accepts. Install capa from
its git tag first, e.g.::

    pip install git+https://github.com/nelsonduarte/capa-language.git@v1.16.0

The only small piece replicated inline is the ``verify_key`` fingerprint
normalisation (it lives inline in ``_manifest._parse_dep``, not behind a
reusable function); its source is cited at the mirror site.

Pure stdlib otherwise (the registry repo has no build system). Shelling
out to ``git`` and ``gpg`` is expected. GPG verification runs against an
ISOLATED keyring built solely from the public keys committed under
``keys/`` (never the ambient user keyring), so a green run proves the
committed key verifies the signatures - nothing else does.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional


# --- Reuse the toolchain's ACTUAL rules (fail hard if capa is absent) ---
#
# Importing these ties the CI to exactly what ``capa`` enforces. If the
# import fails the validator refuses to run rather than fall back to a
# guess, so a green CI can never mean "checked against a stale mirror".
try:
    from capa.pkg._manifest import (  # type: ignore
        MANIFEST_FILENAME,
        _DEP_NAME_RE,
        _PIN_RE,
        _validate_git_url,
    )
    from capa.pkg._registry import (  # type: ignore
        SUPPORTED_REGISTRY_VERSION,
        _REGISTRY_ROOT_KEY,
    )
except ImportError as exc:  # pragma: no cover - CI installs capa first
    sys.stderr.write(
        "FATAL: could not import the 'capa' toolchain, so the git-URL "
        "allow-list, package-name shape, and supported registry version "
        "cannot be checked against what capa actually accepts.\n"
        f"       ({exc})\n\n"
        "Install capa from its git tag before running this validator:\n"
        "  pip install git+https://github.com/nelsonduarte/"
        "capa-language.git@v1.16.0\n"
    )
    raise SystemExit(2)


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INDEX = REPO_ROOT / "index.json"
DEFAULT_SIG = REPO_ROOT / "index.json.asc"
DEFAULT_KEYS_DIR = REPO_ROOT / "keys"

# The registry root fingerprint, pinned here AND cross-checked against
# the toolchain's own ``_REGISTRY_ROOT_KEY`` at startup so a root-key
# rotation in the compiler cannot silently diverge from this repo.
ROOT_FINGERPRINT = "6C1D222D491FB88031E041A536CFB426101AA24B"

# A published tag looks like ``vX.Y.Z`` with an optional pre-release /
# build suffix (``v0.1.2``, ``v1.0.0-rc1``). This is on top of, not
# instead of, the toolchain's ``_PIN_RE`` git-argv-safety shape.
_TAG_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:[.+\-][0-9A-Za-z.+\-]+)?$")

# Fields the toolchain reads for a package entry. ``git`` is the only
# required one (``_registry._entry_from_spec``); the rest are optional
# (``_opt_str``). Rejecting any OTHER key is deliberately stricter than
# the toolchain (which ignores unknown keys) to catch a curator typo
# like ``latset`` that would otherwise silently drop the real field.
_REQUIRED_FIELDS = ("git",)
_OPTIONAL_FIELDS = ("verify_key", "latest", "description")
_KNOWN_FIELDS = frozenset(_REQUIRED_FIELDS + _OPTIONAL_FIELDS)


class ValidationError(Exception):
    """A single per-check failure with a human-readable message."""


def _normalise_fingerprint(value: str) -> str:
    """Normalise a GPG fingerprint the way the manifest parser does.

    Mirror of the inline normalisation in
    ``capa.pkg._manifest._parse_dep`` (verify_key branch): strip spaces
    and colons, upper-case. Kept in sync manually because the toolchain
    performs it inline, not behind a reusable helper. If that inline
    logic ever changes, update this too.
    """
    return value.replace(" ", "").replace(":", "").upper()


def _is_valid_fingerprint(value: str) -> bool:
    normalised = _normalise_fingerprint(value)
    return len(normalised) == 40 and all(
        c in "0123456789ABCDEF" for c in normalised
    )


def _run(cmd: list[str], env: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, capture_output=True, text=True, encoding="utf-8", env=env,
    )


# --------------------------------------------------------------------------
# Schema
# --------------------------------------------------------------------------

def check_schema(index_path: Path) -> tuple[dict, list[str]]:
    """Parse and schema-check the index. Returns ``(packages, notes)``.

    Raises ``ValidationError`` on any structural problem so the caller
    can report it and stop (a malformed index cannot be checked further).
    Per-package field problems are collected and re-raised as one error.
    """
    try:
        raw = index_path.read_bytes()
    except OSError as e:
        raise ValidationError(f"cannot read index at {index_path}: {e}")
    try:
        index = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise ValidationError(f"index.json does not parse as JSON: {e}")

    if not isinstance(index, dict):
        raise ValidationError(
            "index.json top-level value must be a JSON object"
        )

    version = index.get("registry_version")
    # Match the toolchain (``_load_packages``): must be an int, must not
    # exceed the supported version. ``bool`` is an ``int`` subclass, so
    # exclude it explicitly, and require >= 1 - both are deliberately
    # stricter than the toolchain to catch a nonsensical hand-edit.
    if isinstance(version, bool) or not isinstance(version, int):
        raise ValidationError(
            f"'registry_version' must be an integer, got {version!r}"
        )
    if version < 1 or version > SUPPORTED_REGISTRY_VERSION:
        raise ValidationError(
            f"'registry_version' is {version}, but this toolchain "
            f"supports 1..{SUPPORTED_REGISTRY_VERSION}"
        )

    packages = index.get("packages")
    if not isinstance(packages, dict):
        raise ValidationError("'packages' must be a JSON object")

    problems: list[str] = []
    for name, spec in packages.items():
        problems.extend(_check_entry(name, spec))
    if problems:
        raise ValidationError(
            "schema problems:\n  - " + "\n  - ".join(problems)
        )

    notes = [
        f"index.json parses; registry_version={version}; "
        f"{len(packages)} package(s)"
    ]
    return packages, notes


def _check_entry(name: str, spec: object) -> list[str]:
    """Return a list of schema problems for one package entry."""
    problems: list[str] = []

    # Package name must match the toolchain's accepted identifier shape
    # (``_manifest._DEP_NAME_RE`` - the same anchor that stops a name
    # from escaping ``vendor/`` at install time).
    if not _DEP_NAME_RE.match(name):
        problems.append(
            f"{name!r}: package name does not match the accepted name "
            f"shape {_DEP_NAME_RE.pattern}"
        )

    if not isinstance(spec, dict):
        problems.append(f"{name!r}: entry must be a JSON object")
        return problems

    extras = set(spec.keys()) - _KNOWN_FIELDS
    if extras:
        problems.append(
            f"{name!r}: unknown field(s) {sorted(extras)}; allowed: "
            f"{sorted(_KNOWN_FIELDS)} (a typo would silently drop the "
            f"intended field)"
        )

    git = spec.get("git")
    if not isinstance(git, str) or not git:
        problems.append(f"{name!r}: 'git' is required and must be a non-empty string")

    verify_key = spec.get("verify_key")
    if verify_key is not None:
        if not isinstance(verify_key, str):
            problems.append(f"{name!r}: 'verify_key' must be a string")
        elif not _is_valid_fingerprint(verify_key):
            problems.append(
                f"{name!r}: 'verify_key' must be a 40-character hex GPG "
                f"fingerprint (spaces/colons optional), got {verify_key!r}"
            )

    latest = spec.get("latest")
    if latest is not None:
        if not isinstance(latest, str):
            problems.append(f"{name!r}: 'latest' must be a string")
        else:
            if not _TAG_RE.match(latest):
                problems.append(
                    f"{name!r}: 'latest' does not look like a tag "
                    f"(expected vX.Y.Z), got {latest!r}"
                )
            elif not _PIN_RE.match(latest):
                problems.append(
                    f"{name!r}: 'latest' {latest!r} is not a git-argv-safe "
                    f"ref (must match {_PIN_RE.pattern})"
                )

    description = spec.get("description")
    if description is not None and not isinstance(description, str):
        problems.append(f"{name!r}: 'description' must be a string")

    return problems


# --------------------------------------------------------------------------
# Git URL allow-list (reused from the compiler)
# --------------------------------------------------------------------------

def check_git_urls(packages: dict) -> list[str]:
    """Run every ``git`` URL through the compiler's ``_validate_git_url``.

    Reuses the toolchain's own allow-list so the CI cannot accept a URL
    the toolchain would reject (``ext::`` transports, option injection,
    ``file://`` traversal, ...). Raises ``ValidationError`` listing every
    offending entry.
    """
    problems: list[str] = []
    notes: list[str] = []
    for name, spec in packages.items():
        git = spec.get("git")
        if not isinstance(git, str):
            continue  # already reported by the schema check
        try:
            _validate_git_url(Path(MANIFEST_FILENAME), name, git)
        except Exception as e:  # ManifestError
            problems.append(f"{name!r}: disallowed git URL: {e}")
    if problems:
        raise ValidationError(
            "git URL allow-list problems:\n  - " + "\n  - ".join(problems)
        )
    notes.append(
        f"{len(packages)} git URL(s) pass the compiler's _validate_git_url "
        f"allow-list"
    )
    return notes


# --------------------------------------------------------------------------
# GPG: isolated keyring + index signature + tag signatures
# --------------------------------------------------------------------------

def build_keyring(gnupghome: Path, keys_dir: Path) -> list[str]:
    """Import every ``keys/*.asc`` public key into an isolated keyring.

    Returns notes on what was imported. The isolated GNUPGHOME means all
    verification below depends ONLY on the committed keys, never on the
    runner's ambient keyring, so adding a new per-package signer later is
    just dropping its public key under ``keys/`` (no code change).
    """
    gnupghome.mkdir(parents=True, exist_ok=True)
    # Tighten perms so gpg does not warn about an unsafe home.
    try:
        os.chmod(gnupghome, 0o700)
    except OSError:
        pass
    env = _gpg_env(gnupghome)

    key_files = sorted(keys_dir.glob("*.asc")) if keys_dir.is_dir() else []
    if not key_files:
        raise ValidationError(
            f"no public keys found under {keys_dir}; cannot verify "
            f"signatures. Commit the root public key as "
            f"keys/registry-root.asc"
        )
    for key_file in key_files:
        r = _run(["gpg", "--batch", "--import", str(key_file)], env)
        if r.returncode != 0:
            raise ValidationError(
                f"failed to import {key_file.name} into the CI keyring:\n"
                f"{(r.stdout + r.stderr).strip()}"
            )
    return [f"imported {len(key_files)} public key(s) from {keys_dir.name}/"]


def _gpg_homedir(path: Path) -> str:
    """Return a ``GNUPGHOME`` string gpg can actually parse.

    On Linux CI ``str(path)`` is already a POSIX path and is returned
    unchanged. When developing on Windows under Git Bash the gpg on PATH
    is the MSYS build, which cannot parse a Windows-style path; convert
    it with ``cygpath -u`` so the same script runs both places. ``cygpath``
    is absent on the Linux runner, so this is a no-op there.
    """
    p = str(path)
    if sys.platform == "win32" and shutil.which("cygpath"):
        try:
            out = subprocess.run(
                ["cygpath", "-u", p], capture_output=True, text=True,
            )
            if out.returncode == 0 and out.stdout.strip():
                return out.stdout.strip()
        except OSError:
            pass
    return p


def _gpg_env(gnupghome: Path) -> dict:
    env = dict(os.environ)
    env["GNUPGHOME"] = _gpg_homedir(gnupghome)
    return env


def _validsig_primary(status_stdout: str) -> Optional[str]:
    """Return the primary-key fingerprint from a VALIDSIG status line.

    Anchors on the LAST field of ``[GNUPG:] VALIDSIG`` (the primary-key
    fingerprint per GnuPG doc/DETAILS), matching both
    ``_registry._verify_index_signature`` and
    ``_install._verify_signed_pin``.
    """
    for line in status_stdout.splitlines():
        if line.startswith("[GNUPG:] VALIDSIG "):
            parts = line.split()
            if len(parts) >= 3:
                return parts[-1].upper()
    return None


def check_index_signature(
    index_path: Path, sig_path: Path, gnupghome: Path,
) -> list[str]:
    """Verify ``index.json.asc`` is a valid detached signature of the
    CURRENT ``index.json`` bytes, made by the root fingerprint.

    This is the anti-footgun check: edit the index and forget to re-sign,
    or sign with the wrong key, and this goes red. Mirrors
    ``_registry._verify_index_signature`` (VALIDSIG primary == root).
    """
    if not sig_path.exists():
        raise ValidationError(
            f"no detached signature at {sig_path}; the index must ship a "
            f"signature (index.json.asc)"
        )
    env = _gpg_env(gnupghome)
    r = _run(
        ["gpg", "--status-fd", "1", "--verify",
         str(sig_path), str(index_path)],
        env,
    )
    if r.returncode != 0:
        raise ValidationError(
            "index signature does NOT verify against the current "
            "index.json bytes. Either the index was edited without "
            "re-signing, or the signature is by the wrong key.\n"
            f"gpg output:\n{(r.stdout + r.stderr).strip()}"
        )
    fpr = _validsig_primary(r.stdout)
    if fpr is None:
        raise ValidationError(
            "index signature: gpg reported success but emitted no "
            f"VALIDSIG line.\n{(r.stdout + r.stderr).strip()}"
        )
    if fpr != ROOT_FINGERPRINT:
        raise ValidationError(
            f"index is signed by {fpr}, but the registry root key is "
            f"{ROOT_FINGERPRINT}"
        )
    return [f"index.json.asc VALID over current index.json by root {fpr}"]


def check_tag_signatures(packages: dict, gnupghome: Path) -> list[str]:
    """For every package with a ``verify_key``, confirm the ``latest``
    tag EXISTS in the target repo and its tag object is GPG-signed by
    that ``verify_key``.

    Existence is a read-only ``git ls-remote --tags``; the signature is
    checked by fetching the tag into a throwaway repo and running
    ``git verify-tag --raw`` (mirrors ``_install._verify_signed_pin``:
    anchor on the VALIDSIG primary fingerprint). Packages without a
    ``verify_key`` are skipped (the toolchain installs them without
    tag verification).
    """
    env = _gpg_env(gnupghome)
    problems: list[str] = []
    notes: list[str] = []
    checked = 0
    for name, spec in packages.items():
        if not isinstance(spec, dict):
            continue
        verify_key = spec.get("verify_key")
        git = spec.get("git")
        latest = spec.get("latest")
        if not isinstance(verify_key, str) or not verify_key:
            notes.append(f"{name}: no verify_key, tag signature not checked")
            continue
        if not isinstance(git, str) or not isinstance(latest, str):
            problems.append(
                f"{name!r}: has verify_key but no usable git/latest to "
                f"check the tag signature"
            )
            continue
        expected = _normalise_fingerprint(verify_key)
        try:
            _verify_one_tag(name, git, latest, expected, env)
        except ValidationError as e:
            problems.append(str(e))
            continue
        checked += 1
        notes.append(
            f"{name} {latest}: tag exists in {git} and is signed by "
            f"{expected}"
        )
    if problems:
        raise ValidationError(
            "tag signature problems:\n  - " + "\n  - ".join(problems)
        )
    notes.insert(0, f"{checked} latest tag(s) verified (exist + signed)")
    return notes


def _verify_one_tag(
    name: str, git: str, tag: str, expected: str, env: dict,
) -> None:
    # 1. Existence: read-only ls-remote (does not fetch objects).
    r = _run(["git", "ls-remote", "--tags", git, f"refs/tags/{tag}"], env)
    if r.returncode != 0:
        raise ValidationError(
            f"{name!r}: 'git ls-remote' failed on {git}:\n{r.stderr.strip()}"
        )
    if f"refs/tags/{tag}" not in r.stdout:
        raise ValidationError(
            f"{name!r}: latest tag {tag!r} does not exist in {git}"
        )

    # 2. Signature: fetch the tag into a throwaway repo and verify-tag.
    with tempfile.TemporaryDirectory(prefix="capa_tagverify_") as td:
        repo = Path(td)
        init = _run(["git", "init", "-q", str(repo)], env)
        if init.returncode != 0:
            raise ValidationError(
                f"{name!r}: could not init a temp repo:\n{init.stderr.strip()}"
            )
        fetch = _run(
            ["git", "-C", str(repo), "fetch", "--no-tags", "-q", git,
             f"refs/tags/{tag}:refs/tags/{tag}"],
            env,
        )
        if fetch.returncode != 0:
            raise ValidationError(
                f"{name!r}: could not fetch tag {tag!r} from {git}:\n"
                f"{fetch.stderr.strip()}"
            )
        v = _run(
            ["git", "-C", str(repo), "verify-tag", "--raw", tag], env,
        )
        if v.returncode != 0:
            raise ValidationError(
                f"{name!r}: tag {tag!r} signature does not verify (unsigned, "
                f"unknown key, or invalid). Expected signer {expected}.\n"
                f"git output:\n{v.stderr.strip()}"
            )
        fpr = _validsig_primary(v.stderr)
        if fpr is None:
            raise ValidationError(
                f"{name!r}: tag {tag!r} verified but gpg emitted no VALIDSIG "
                f"line.\n{v.stderr.strip()}"
            )
        if fpr != expected:
            raise ValidationError(
                f"{name!r}: tag {tag!r} is signed by {fpr}, but the "
                f"registry declares verify_key {expected}"
            )


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------

def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--index", type=Path, default=DEFAULT_INDEX,
        help="path to index.json (default: repo root)",
    )
    parser.add_argument(
        "--sig", type=Path, default=DEFAULT_SIG,
        help="path to index.json.asc (default: repo root)",
    )
    parser.add_argument(
        "--keys-dir", type=Path, default=DEFAULT_KEYS_DIR,
        help="directory of trusted public keys (default: keys/)",
    )
    parser.add_argument(
        "--skip-network", action="store_true",
        help="skip the tag existence + signature checks (offline schema "
             "and index-signature validation only)",
    )
    args = parser.parse_args(argv)

    # Guard against a root-key rotation in the toolchain silently
    # diverging from the key this repo pins and ships.
    if _REGISTRY_ROOT_KEY and _REGISTRY_ROOT_KEY.upper() != ROOT_FINGERPRINT:
        sys.stderr.write(
            f"FATAL: the toolchain's registry root key "
            f"({_REGISTRY_ROOT_KEY}) differs from the fingerprint this "
            f"validator pins ({ROOT_FINGERPRINT}). Update keys/ and "
            f"ROOT_FINGERPRINT together.\n"
        )
        return 2

    ok: list[str] = []
    try:
        packages, notes = check_schema(args.index)
        ok += notes
        ok += check_git_urls(packages)

        with tempfile.TemporaryDirectory(prefix="capa_regkeyring_") as kd:
            gnupghome = Path(kd)
            ok += build_keyring(gnupghome, args.keys_dir)
            ok += check_index_signature(args.index, args.sig, gnupghome)
            if args.skip_network:
                ok.append("tag checks SKIPPED (--skip-network)")
            else:
                ok += check_tag_signatures(packages, gnupghome)
    except ValidationError as e:
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
