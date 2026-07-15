"""Regression tests for the trust-critical registry helpers.

Each test pins one hardening guarantee of ``scripts/_registry_lib.py``:

  * W1: a git-bearing entry MUST carry a ``verify_key`` and cannot opt out
    of tag-signature verification, at the schema layer, the verification
    layer, and the sign path.
  * S1: a tag / pin value with a trailing newline is rejected.
  * S2: an unknown top-level index key is rejected.
  * the real committed ``index.json`` (all 14 entries) still validates.

Pure offline: the W1 sign-path and verification-layer checks fail BEFORE
any git / gpg call, so no network or private key is needed here.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import _registry_lib as lib  # noqa: E402
from sign_index import sign_and_verify  # noqa: E402

ROOT = lib.ROOT_FINGERPRINT


def _good_entry() -> dict:
    return {
        "git": "https://github.com/nelsonduarte/capa_base64",
        "verify_key": ROOT,
        "latest": "v0.1.0",
        "description": "example",
    }


def _index_with(packages: dict, **top) -> dict:
    index = {"registry_version": 1, "updated": "2026-07-15", "packages": packages}
    index.update(top)
    return index


# --- W1: verify_key required + fail-closed for git-bearing entries --------

def test_git_entry_without_verify_key_rejected_by_check_entry():
    spec = {"git": "https://github.com/nelsonduarte/capa_base64", "latest": "v0.1.0"}
    problems = lib.check_entry("capa_base64", spec)
    assert any("verify_key" in p and "required" in p for p in problems)


def test_git_entry_without_verify_key_rejected_by_validate_index_dict():
    index = _index_with(
        {"capa_base64": {"git": "https://github.com/nelsonduarte/capa_base64",
                         "latest": "v0.1.0"}}
    )
    with pytest.raises(lib.ValidationError, match="verify_key"):
        lib.validate_index_dict(index)


def test_git_entry_without_verify_key_fails_tag_signatures():
    packages = {
        "capa_base64": {"git": "https://github.com/nelsonduarte/capa_base64",
                        "latest": "v0.1.0"}
    }
    # Fails in-loop before any network / gpg call, so the gnupghome path is
    # never touched.
    with pytest.raises(lib.ValidationError, match="tag signature problems"):
        lib.check_tag_signatures(packages, Path(tempfile.gettempdir()))


def test_git_entry_without_verify_key_cannot_be_signed():
    index = _index_with(
        {"capa_base64": {"git": "https://github.com/nelsonduarte/capa_base64",
                         "latest": "v0.1.0"}}
    )
    with tempfile.TemporaryDirectory() as td:
        index_path = Path(td) / "index.json"
        sig_path = Path(td) / "index.json.asc"
        index_path.write_text(json.dumps(index), encoding="utf-8")
        # The schema layer refuses before any signing, so no .asc is
        # produced even with the network tag check disabled.
        with pytest.raises(lib.ValidationError, match="verify_key"):
            sign_and_verify(index_path, sig_path, lib.DEFAULT_KEYS_DIR,
                            verify_tags=False)
        assert not sig_path.exists()


def test_entry_without_git_and_without_verify_key_is_noted_not_failed():
    # No git URL means there is nothing to verify; not a fail-closed case.
    notes = lib.check_tag_signatures({"weird": {}}, Path(tempfile.gettempdir()))
    assert any("nothing to check" in n for n in notes)


# --- S1: trailing-newline tag / pin rejected ------------------------------

@pytest.mark.parametrize("bad", ["v0.1.0\n", "v1.2.3\n", "v1.0.0-rc1\n"])
def test_trailing_newline_tag_rejected(bad):
    spec = {"git": "https://github.com/nelsonduarte/capa_base64",
            "verify_key": ROOT, "latest": bad}
    problems = lib.check_entry("capa_base64", spec)
    assert any("latest" in p for p in problems)


@pytest.mark.parametrize("good", ["v0.1.0", "v1.2.3", "v1.0.0-rc1", "v0.1.2+build"])
def test_valid_tags_still_accepted(good):
    spec = {"git": "https://github.com/nelsonduarte/capa_base64",
            "verify_key": ROOT, "latest": good}
    assert lib.check_entry("capa_base64", spec) == []


def test_tag_re_and_pin_reject_trailing_newline_directly():
    assert lib._TAG_RE.match("v1.2.3\n") is None
    assert lib._PIN_RE.fullmatch("v1.2.3\n") is None
    assert lib._TAG_RE.match("v1.2.3") is not None
    assert lib._PIN_RE.fullmatch("v1.2.3") is not None


# --- S2: unknown top-level key rejected -----------------------------------

def test_unknown_top_level_key_rejected():
    index = _index_with({"capa_base64": _good_entry()}, sneaky="value")
    with pytest.raises(lib.ValidationError, match="unknown top-level key"):
        lib.validate_index_dict(index)


def test_known_top_level_keys_accepted():
    index = _index_with({"capa_base64": _good_entry()})
    packages, _notes = lib.validate_index_dict(index)
    assert "capa_base64" in packages


# --- The real committed index still validates -----------------------------

def test_real_index_schema_still_validates():
    packages, _notes = lib.check_schema(lib.DEFAULT_INDEX)
    assert len(packages) == 14
    for name, spec in packages.items():
        assert lib.check_entry(name, spec) == [], name
        assert spec.get("verify_key")  # every entry carries the root key
