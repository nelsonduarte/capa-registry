"""Shared trust-critical helpers for the capa-registry tooling.

Single source of truth for the checks and index-manipulation the whole
tool suite depends on:

  * loading + canonically serialising ``index.json`` (exact 2-space
    indent, per-entry field order, packages sorted by name, trailing
    newline) so a tool edit is a MINIMAL diff, never a reserialisation;
  * the schema check;
  * the git-URL allow-list check, delegated to the Capa toolchain's OWN
    ``_validate_git_url`` so nothing here can drift from what ``capa``
    accepts;
  * GPG keyring setup (an isolated keyring built only from ``keys/``);
  * index-signature verification (detached sig over the exact bytes);
  * remote tag listing + "does this tag exist and is it signed by this
    verify_key", including picking the newest SIGNED tag.

Both the CI validator (``validate_index.py``, which runs with the PUBLIC
key only) and the LOCAL curator tools (``sign_index.py``,
``refresh_latest.py``, ``add_package.py``, which need the PRIVATE root
key in the local gpg keyring to sign) import from here, so the
trust-critical logic lives in exactly one place.

Pure stdlib, shelling out to ``git`` and ``gpg``. The toolchain rules are
IMPORTED from ``capa`` (install it from a git tag first); the module
refuses to load if ``capa`` is absent.
"""

from __future__ import annotations

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
# Importing these ties the tooling to exactly what ``capa`` enforces. If
# the import fails we refuse to run rather than fall back to a guess, so a
# green run can never mean "checked against a stale mirror".
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
except ImportError as exc:  # pragma: no cover - callers install capa first
    sys.stderr.write(
        "FATAL: could not import the 'capa' toolchain, so the git-URL "
        "allow-list, package-name shape, and supported registry version "
        "cannot be checked against what capa actually accepts.\n"
        f"       ({exc})\n\n"
        "Install capa from its git tag first:\n"
        "  pip install git+https://github.com/nelsonduarte/"
        "capa-language.git@v1.16.0\n"
    )
    raise SystemExit(2)


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INDEX = REPO_ROOT / "index.json"
DEFAULT_SIG = REPO_ROOT / "index.json.asc"
DEFAULT_KEYS_DIR = REPO_ROOT / "keys"

# The registry root fingerprint, pinned here AND cross-checked against the
# toolchain's own ``_REGISTRY_ROOT_KEY`` so a root-key rotation in the
# compiler cannot silently diverge from this repo (see
# ``assert_root_key_consistency``).
ROOT_FINGERPRINT = "6C1D222D491FB88031E041A536CFB426101AA24B"

# A published tag looks like ``vX.Y.Z`` with an optional semver
# pre-release (``-rc1``) and/or build metadata (``+build``): ``v0.1.2``,
# ``v1.0.0-rc1``, ``v0.1.2+build``. The two suffixes are kept in
# SEPARATE groups so precedence can follow semver (pre-release lowers
# precedence; build metadata is ignored). On top of, not instead of, the
# toolchain's ``_PIN_RE`` git-argv-safety shape.
_TAG_RE = re.compile(
    r"^v(?P<maj>[0-9]+)\.(?P<min>[0-9]+)\.(?P<pat>[0-9]+)"
    r"(?:-(?P<pre>[0-9A-Za-z.-]+))?"
    r"(?:\+(?P<build>[0-9A-Za-z.-]+))?$"
)

# Fields the toolchain reads for a package entry. ``git`` is the only
# required one (``_registry._entry_from_spec``); the rest are optional
# (``_opt_str``). They are serialised in THIS order. Rejecting any OTHER
# key is deliberately stricter than the toolchain (which ignores unknown
# keys) to catch a curator typo like ``latset`` that would otherwise
# silently drop the intended field.
_REQUIRED_FIELDS = ("git",)
_OPTIONAL_FIELDS = ("verify_key", "latest", "description")
FIELD_ORDER = _REQUIRED_FIELDS + _OPTIONAL_FIELDS
_KNOWN_FIELDS = frozenset(FIELD_ORDER)


class ValidationError(Exception):
    """A single per-check failure with a human-readable message."""


# --------------------------------------------------------------------------
# Fingerprints
# --------------------------------------------------------------------------

def normalise_fingerprint(value: str) -> str:
    """Normalise a GPG fingerprint the way the manifest parser does.

    Mirror of the inline normalisation in
    ``capa.pkg._manifest._parse_dep`` (verify_key branch): strip spaces
    and colons, upper-case. Kept in sync manually because the toolchain
    performs it inline, not behind a reusable helper.
    """
    return value.replace(" ", "").replace(":", "").upper()


def is_valid_fingerprint(value: str) -> bool:
    normalised = normalise_fingerprint(value)
    return len(normalised) == 40 and all(
        c in "0123456789ABCDEF" for c in normalised
    )


def assert_root_key_consistency() -> None:
    """Refuse to run if the toolchain's root key diverges from ours.

    Guards against a root-key rotation in the compiler silently
    diverging from the key this repo pins and ships under ``keys/``.
    """
    if _REGISTRY_ROOT_KEY and _REGISTRY_ROOT_KEY.upper() != ROOT_FINGERPRINT:
        raise ValidationError(
            f"the toolchain's registry root key ({_REGISTRY_ROOT_KEY}) "
            f"differs from the fingerprint this repo pins "
            f"({ROOT_FINGERPRINT}); update keys/ and ROOT_FINGERPRINT "
            f"together"
        )


def _run(cmd: list[str], env: Optional[dict] = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, capture_output=True, text=True, encoding="utf-8", env=env,
    )


# --------------------------------------------------------------------------
# Load + canonical serialise
# --------------------------------------------------------------------------

def load_index(index_path: Path) -> tuple[bytes, dict]:
    """Return ``(raw_bytes, parsed_dict)`` for the index at ``index_path``.

    The raw bytes are what a detached signature is verified against; the
    dict is what the tools mutate.
    """
    try:
        raw = index_path.read_bytes()
    except OSError as e:
        raise ValidationError(f"cannot read index at {index_path}: {e}")
    try:
        index = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise ValidationError(f"{index_path.name} does not parse as JSON: {e}")
    return raw, index


def serialise_index(index: dict) -> bytes:
    """Serialise the index in the file's EXACT canonical shape.

    Top-level order ``registry_version, updated, packages``; packages
    sorted by name; each entry's fields in ``FIELD_ORDER`` (absent
    optional fields omitted); 2-space indent; UTF-8; trailing newline.
    This reproduces the committed ``index.json`` byte-for-byte, so a tool
    edit yields a minimal diff rather than a whole-file reserialisation.
    """
    packages = index.get("packages", {})
    canonical_pkgs = {
        name: {k: packages[name][k] for k in FIELD_ORDER if k in packages[name]}
        for name in sorted(packages)
    }
    ordered: dict = {}
    if "registry_version" in index:
        ordered["registry_version"] = index["registry_version"]
    if "updated" in index:
        ordered["updated"] = index["updated"]
    ordered["packages"] = canonical_pkgs
    text = json.dumps(ordered, indent=2, ensure_ascii=False)
    return text.encode("utf-8") + b"\n"


def write_index(index_path: Path, index: dict) -> None:
    """Write the index in canonical form."""
    index_path.write_bytes(serialise_index(index))


# --------------------------------------------------------------------------
# Schema
# --------------------------------------------------------------------------

def validate_index_dict(index: dict) -> tuple[dict, list[str]]:
    """Schema-check a parsed index dict. Returns ``(packages, notes)``.

    Raises ``ValidationError`` on any structural problem. Per-package
    field problems are collected and raised as one error.
    """
    if not isinstance(index, dict):
        raise ValidationError("index top-level value must be a JSON object")

    version = index.get("registry_version")
    # Match the toolchain (``_load_packages``): must be an int, must not
    # exceed the supported version. ``bool`` is an ``int`` subclass, so
    # exclude it, and require >= 1 - both deliberately stricter than the
    # toolchain to catch a nonsensical hand-edit.
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
        problems.extend(check_entry(name, spec))
    if problems:
        raise ValidationError(
            "schema problems:\n  - " + "\n  - ".join(problems)
        )

    notes = [
        f"index.json parses; registry_version={version}; "
        f"{len(packages)} package(s)"
    ]
    return packages, notes


def check_schema(index_path: Path) -> tuple[dict, list[str]]:
    """Load and schema-check the index at ``index_path``."""
    _raw, index = load_index(index_path)
    return validate_index_dict(index)


def check_entry(name: str, spec: object) -> list[str]:
    """Return a list of schema problems for one package entry."""
    problems: list[str] = []

    # Package name must match the toolchain's accepted identifier shape
    # (``_manifest._DEP_NAME_RE`` - the same anchor that stops a name from
    # escaping ``vendor/`` at install time).
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
        elif not is_valid_fingerprint(verify_key):
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

def validate_git_url(name: str, git: str) -> None:
    """Run one ``git`` URL through the compiler's ``_validate_git_url``.

    Raises ``ValidationError`` (re-wrapping the toolchain's
    ``ManifestError``) so a poisoned URL is refused with the toolchain's
    own reason.
    """
    try:
        _validate_git_url(Path(MANIFEST_FILENAME), name, git)
    except Exception as e:  # ManifestError
        raise ValidationError(f"{name!r}: disallowed git URL: {e}")


def check_git_urls(packages: dict) -> list[str]:
    """Run every ``git`` URL through the compiler's allow-list."""
    problems: list[str] = []
    for name, spec in packages.items():
        git = spec.get("git")
        if not isinstance(git, str):
            continue  # already reported by the schema check
        try:
            validate_git_url(name, git)
        except ValidationError as e:
            problems.append(str(e))
    if problems:
        raise ValidationError(
            "git URL allow-list problems:\n  - " + "\n  - ".join(problems)
        )
    return [
        f"{len(packages)} git URL(s) pass the compiler's _validate_git_url "
        f"allow-list"
    ]


# --------------------------------------------------------------------------
# GPG: isolated keyring + index signature
# --------------------------------------------------------------------------

def _gpg_homedir(path: Path) -> str:
    """Return a ``GNUPGHOME`` string gpg can actually parse.

    On Linux CI ``str(path)`` is already POSIX and returned unchanged.
    Under Windows Git Bash the gpg on PATH is the MSYS build, which cannot
    parse a Windows-style path; convert with ``cygpath -u`` so the same
    code runs both places. ``cygpath`` is absent on the Linux runner, so
    this is a no-op there.
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


def gpg_env(gnupghome: Path) -> dict:
    """A subprocess env with ``GNUPGHOME`` pointed at ``gnupghome``."""
    env = dict(os.environ)
    env["GNUPGHOME"] = _gpg_homedir(gnupghome)
    return env


def build_keyring(gnupghome: Path, keys_dir: Path) -> list[str]:
    """Import every ``keys/*.asc`` public key into an isolated keyring.

    The isolated GNUPGHOME means verification depends ONLY on the
    committed keys, never on the runner's ambient keyring, so adding a new
    per-package signer later is just dropping its public key under
    ``keys/`` (no code change).
    """
    gnupghome.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(gnupghome, 0o700)
    except OSError:
        pass
    env = gpg_env(gnupghome)

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
                f"failed to import {key_file.name} into the keyring:\n"
                f"{(r.stdout + r.stderr).strip()}"
            )
    return [f"imported {len(key_files)} public key(s) from {keys_dir.name}/"]


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
    """Verify ``sig_path`` is a valid detached signature of the CURRENT
    ``index_path`` bytes, made by the root fingerprint.

    Mirrors ``_registry._verify_index_signature`` (VALIDSIG primary ==
    root). This is the anti-footgun check: edit the index and forget to
    re-sign, or sign with the wrong key, and it fails.
    """
    if not sig_path.exists():
        raise ValidationError(
            f"no detached signature at {sig_path}; the index must ship a "
            f"signature (index.json.asc)"
        )
    env = gpg_env(gnupghome)
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


def sign_index(index_path: Path, sig_path: Path) -> None:
    """Produce a detached armored signature of the exact index bytes.

    Runs ``gpg --armor --detach-sign --local-user <ROOT_KEY>`` using the
    CURATOR'S default keyring (which holds the PRIVATE root key); it does
    NOT use an isolated keyring. LOCAL curator use only - CI has the
    public key only and can never sign.
    """
    r = _run([
        "gpg", "--batch", "--yes", "--armor", "--detach-sign",
        "--local-user", ROOT_FINGERPRINT,
        "--output", str(sig_path), str(index_path),
    ])
    if r.returncode != 0:
        raise ValidationError(
            "signing failed. This tool is LOCAL-only and needs the root "
            f"PRIVATE key ({ROOT_FINGERPRINT}) in your gpg keyring.\n"
            f"gpg output:\n{(r.stdout + r.stderr).strip()}"
        )


# --------------------------------------------------------------------------
# Remote tags: existence, signature, newest signed
# --------------------------------------------------------------------------

def parse_tag_version(tag: str) -> Optional[tuple]:
    """A sort key for ``vX.Y.Z[-pre][+build]`` tags, or None if not one.

    Release versions sort ABOVE a pre-release of the same X.Y.Z (higher
    key), so ``v1.0.0`` beats ``v1.0.0-rc1``. Pre-releases order lexically
    by their identifier (a coarse but stable rule; the registry uses plain
    vX.Y.Z tags). Build metadata (``+build``) is IGNORED for precedence
    per semver, so ``v0.1.2+build`` compares EQUAL to ``v0.1.2`` (and both
    sit above ``v0.1.2-rc1``).
    """
    m = _TAG_RE.match(tag)
    if m is None:
        return None
    pre = m.group("pre")
    return (
        int(m.group("maj")), int(m.group("min")), int(m.group("pat")),
        1 if pre is None else 0,
        pre or "",
    )


def remote_tags(git: str, env: dict) -> list[str]:
    """Return the tag names published by the repo at ``git``.

    Read-only ``git ls-remote --tags``; strips the ``refs/tags/`` prefix
    and the ``^{}`` peeled-tag suffix, de-duplicated.
    """
    r = _run(["git", "ls-remote", "--tags", git], env)
    if r.returncode != 0:
        raise ValidationError(
            f"'git ls-remote' failed on {git}:\n{r.stderr.strip()}"
        )
    names: set[str] = set()
    for line in r.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) != 2:
            continue
        ref = parts[1]
        if not ref.startswith("refs/tags/"):
            continue
        name = ref[len("refs/tags/"):]
        if name.endswith("^{}"):
            name = name[:-3]
        names.add(name)
    return sorted(names)


def remote_tag_exists(git: str, tag: str, env: dict) -> bool:
    r = _run(["git", "ls-remote", "--tags", git, f"refs/tags/{tag}"], env)
    if r.returncode != 0:
        raise ValidationError(
            f"'git ls-remote' failed on {git}:\n{r.stderr.strip()}"
        )
    return f"refs/tags/{tag}" in r.stdout


def _fetch_tag(repo: Path, git: str, tag: str, env: dict) -> None:
    init = _run(["git", "init", "-q", str(repo)], env)
    if init.returncode != 0:
        raise ValidationError(
            f"could not init a temp repo:\n{init.stderr.strip()}"
        )
    fetch = _run(
        ["git", "-C", str(repo), "fetch", "--no-tags", "-q", git,
         f"refs/tags/{tag}:refs/tags/{tag}"],
        env,
    )
    if fetch.returncode != 0:
        raise ValidationError(
            f"could not fetch tag {tag!r} from {git}:\n{fetch.stderr.strip()}"
        )


def tag_signed_by(git: str, tag: str, expected: str, env: dict) -> Optional[str]:
    """Return None if ``tag`` in ``git`` is GPG-signed by ``expected``,
    else a human-readable reason.

    Mirrors ``_install._verify_signed_pin``: fetch the tag into a
    throwaway repo, ``git verify-tag --raw``, anchor on the VALIDSIG
    primary fingerprint. ``expected`` must be a normalised fingerprint.
    Verification runs under the caller's ``env`` (point ``GNUPGHOME`` at
    the isolated keyring built from ``keys/``).
    """
    with tempfile.TemporaryDirectory(prefix="capa_tagverify_") as td:
        repo = Path(td)
        try:
            _fetch_tag(repo, git, tag, env)
        except ValidationError as e:
            return str(e)
        v = _run(["git", "-C", str(repo), "verify-tag", "--raw", tag], env)
        if v.returncode != 0:
            return (
                f"tag {tag!r} signature does not verify (unsigned, unknown "
                f"key, or invalid); expected signer {expected}.\n"
                f"git output:\n{v.stderr.strip()}"
            )
        fpr = _validsig_primary(v.stderr)
        if fpr is None:
            return (
                f"tag {tag!r} verified but gpg emitted no VALIDSIG line.\n"
                f"{v.stderr.strip()}"
            )
        if fpr != expected:
            return (
                f"tag {tag!r} is signed by {fpr}, but the expected "
                f"verify_key is {expected}"
            )
    return None


def check_tag_signatures(packages: dict, gnupghome: Path) -> list[str]:
    """For every package with a ``verify_key``, confirm the ``latest`` tag
    exists and is signed by that key.

    Packages without a ``verify_key`` are skipped (the toolchain installs
    them without tag verification).
    """
    env = gpg_env(gnupghome)
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
        expected = normalise_fingerprint(verify_key)
        try:
            if not remote_tag_exists(git, latest, env):
                problems.append(
                    f"{name!r}: latest tag {latest!r} does not exist in {git}"
                )
                continue
        except ValidationError as e:
            problems.append(f"{name!r}: {e}")
            continue
        reason = tag_signed_by(git, latest, expected, env)
        if reason is not None:
            problems.append(f"{name!r}: {reason}")
            continue
        checked += 1
        notes.append(
            f"{name} {latest}: tag exists in {git} and is signed by {expected}"
        )
    if problems:
        raise ValidationError(
            "tag signature problems:\n  - " + "\n  - ".join(problems)
        )
    notes.insert(0, f"{checked} latest tag(s) verified (exist + signed)")
    return notes


def newest_signed_tag(git: str, expected: str, env: dict) -> Optional[str]:
    """Return the highest-semver ``vX.Y.Z`` tag in ``git`` that is
    GPG-signed by ``expected``, or None if none is.

    Considers only tags matching the ``vX.Y.Z`` shape, sorted newest
    first, and returns the FIRST one whose signature verifies - so an
    unsigned (or wrong-key) newer tag is skipped in favour of the newest
    correctly signed one, never the other way round.
    """
    candidates = [t for t in remote_tags(git, env) if parse_tag_version(t)]
    candidates.sort(key=parse_tag_version, reverse=True)
    for tag in candidates:
        if tag_signed_by(git, tag, expected, env) is None:
            return tag
    return None


def read_capa_toml_description(git: str, tag: str, env: dict) -> Optional[str]:
    """Best-effort read of ``[package].description`` from the package's
    ``capa.toml`` at ``tag``, or None when there is none.

    Fetches the tag and reads the raw ``capa.toml`` blob. Parsed with a
    tolerant raw TOML read (not capa's strict manifest parser), so a
    ``description`` key is picked up if present. In practice the current
    registry packages are single-module ``.capa`` libraries with no
    ``capa.toml``, so this usually returns None and the caller supplies
    the description another way.
    """
    if sys.version_info >= (3, 11):
        import tomllib as _toml
    else:  # pragma: no cover - dev-only path
        try:
            import tomli as _toml  # type: ignore
        except ImportError:
            return None
    with tempfile.TemporaryDirectory(prefix="capa_desc_") as td:
        repo = Path(td)
        try:
            _fetch_tag(repo, git, tag, env)
        except ValidationError:
            return None
        show = _run(["git", "-C", str(repo), "show", f"{tag}:capa.toml"], env)
        if show.returncode != 0:
            return None
        try:
            data = _toml.loads(show.stdout)
        except Exception:  # noqa: BLE001 - any malformed toml => no description
            return None
    pkg = data.get("package") if isinstance(data, dict) else None
    desc = pkg.get("description") if isinstance(pkg, dict) else None
    return desc if isinstance(desc, str) and desc else None
