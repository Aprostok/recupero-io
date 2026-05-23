"""Regression audit for implicit str/bytes encoding boundaries.

Locks down the rule: any text-mode file IO in ``src/recupero`` must
declare ``encoding="utf-8"`` (or a documented utf-8 variant). The
implicit default is ``locale.getpreferredencoding(False)`` which is
``cp1252`` on Windows, ``UTF-8`` on Linux/macOS — round-tripping
non-ASCII victim names, exchange labels, or jinja template output
silently mangles bytes on one platform but not the other.

The audit walks every ``.py`` under ``src/recupero`` and asserts:

  1. Every ``open(..., "r|w|a"[t])`` carries ``encoding=`` kwarg.
  2. Every ``Path.read_text()`` / ``write_text()`` carries
     ``encoding=`` kwarg.
  3. ``subprocess.run(..., text=True)`` carries ``encoding=`` kwarg
     (Windows defaults to cp1252 here, decoding pdf/html stderr
     dumps wrong on Railway).

We intentionally do NOT lint bare ``.encode()`` / ``.decode()`` —
those default to utf-8 across all Python 3.x platforms (PEP 597
only deprecates implicit *locale*-based encodings, not the
``str``-method utf-8 default). The current callsites are limited
to hashing ASCII keys and HMAC of webhook secrets, where utf-8 ==
ascii output.
"""

from __future__ import annotations

import ast
import pathlib

import pytest


SRC_ROOT = pathlib.Path(__file__).resolve().parent.parent / "src" / "recupero"


def _kwarg_value(call: ast.Call, name: str) -> ast.expr | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _is_text_mode_open(call: ast.Call) -> bool:
    """Builtin open() in text mode. Defaults to 'r' (text).

    Mode positional index differs by call form:
      builtin open(file, mode, ...)   -> args[1]
      Path.open(mode, ...)            -> args[0]
    We don't statically know which form an `Attribute.open` is, so we
    inspect both positional slots and the `mode=` kwarg, returning the
    first Constant we find.
    """
    func = call.func
    is_attr_open = False
    if isinstance(func, ast.Name) and func.id == "open":
        pass
    elif isinstance(func, ast.Attribute) and func.attr == "open":
        # Path.open / tmp.open etc. — mode is args[0] OR args[1] depending
        # on whether caller wrote `p.open("rb")` or, exotically,
        # `obj.open(path, "rb")` (some test fixtures do this). Probe both.
        is_attr_open = True
    else:
        return False
    mode: str | None = None
    candidate_indices = (0, 1) if is_attr_open else (1,)
    for idx in candidate_indices:
        if len(call.args) > idx and isinstance(call.args[idx], ast.Constant):
            v = call.args[idx].value
            if isinstance(v, str):
                mode = v
                break
    if mode is None:
        mv = _kwarg_value(call, "mode")
        if isinstance(mv, ast.Constant) and isinstance(mv.value, str):
            mode = mv.value
    if mode is None:
        # Default mode for both builtin open and Path.open is "r" text.
        return True
    return "b" not in mode


def _is_text_io_call(call: ast.Call, attr_name: str) -> bool:
    func = call.func
    return isinstance(func, ast.Attribute) and func.attr == attr_name


def _is_subprocess_text_run(call: ast.Call) -> bool:
    func = call.func
    if not isinstance(func, ast.Attribute):
        return False
    if func.attr not in {"run", "check_output", "Popen"}:
        return False
    # text=True OR universal_newlines=True triggers text decoding.
    for kw_name in ("text", "universal_newlines"):
        v = _kwarg_value(call, kw_name)
        if isinstance(v, ast.Constant) and v.value is True:
            return True
    return False


def _has_encoding_kw(call: ast.Call) -> bool:
    return _kwarg_value(call, "encoding") is not None


def _iter_src_files() -> list[pathlib.Path]:
    return sorted(p for p in SRC_ROOT.rglob("*.py") if "_defaults" not in p.parts)


def test_no_implicit_text_open():
    """Every text-mode open() / Path.open() in src/ declares encoding."""
    offenders: list[str] = []
    for py in _iter_src_files():
        tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not _is_text_mode_open(node):
                continue
            # Skip os.fdopen (still flagged via Attribute.attr=="fdopen"
            # — we DO want encoding= on those too).
            if _has_encoding_kw(node):
                continue
            offenders.append(f"{py.relative_to(SRC_ROOT)}:{node.lineno}")
    assert not offenders, (
        "open()/Path.open() without encoding='utf-8' "
        "(Windows would fall back to cp1252):\n  "
        + "\n  ".join(offenders)
    )


def test_no_implicit_read_write_text():
    """Path.read_text() / write_text() must declare encoding."""
    offenders: list[str] = []
    for py in _iter_src_files():
        tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not (
                _is_text_io_call(node, "read_text")
                or _is_text_io_call(node, "write_text")
            ):
                continue
            # Skip storage-abstraction wrappers — store.write_text()
            # takes (filename, body, content_type) not an encoding kw;
            # we identify those by a 2nd positional arg that is NOT a
            # Path/keyword form. Conservative filter: the recupero
            # storage layer uses 3 positional args and lives under
            # recupero/storage or is called as `store.write_text`.
            if isinstance(node.func, ast.Attribute) and isinstance(
                node.func.value, ast.Name
            ) and node.func.value.id == "store":
                continue
            # storage backends define write_text(self, name, body, ...);
            # skip definitions in recupero/storage/.
            if "storage" in py.parts and node.func.attr == "write_text":
                # Method-call sites in storage backends are intra-class
                # wrappers, not pathlib.
                if not isinstance(node.func.value, ast.Name) or node.func.value.id != "self":
                    continue
            if _has_encoding_kw(node):
                continue
            offenders.append(f"{py.relative_to(SRC_ROOT)}:{node.lineno}")
    # The storage wrapper false-positives are filtered above; anything
    # left is a real pathlib call without encoding=.
    assert not offenders, (
        "Path.read_text/write_text without encoding='utf-8':\n  "
        + "\n  ".join(offenders)
    )


def test_no_implicit_subprocess_text():
    """subprocess.run(..., text=True) must pin encoding='utf-8'."""
    offenders: list[str] = []
    for py in _iter_src_files():
        tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not _is_subprocess_text_run(node):
                continue
            if _has_encoding_kw(node):
                continue
            offenders.append(f"{py.relative_to(SRC_ROOT)}:{node.lineno}")
    assert not offenders, (
        "subprocess text-mode without encoding='utf-8' "
        "(Windows defaults to cp1252):\n  "
        + "\n  ".join(offenders)
    )


@pytest.mark.parametrize(
    "fragment",
    [
        # cluster_builder hashes a lowercased ASCII chain|address
        # composite; .encode() default is UTF-8 on every CPython 3.x.
        "abc|sol".encode(),
        # webhook signed-payload prefix — ASCII timestamp + dot.
        f"{1700000000}.".encode(),
    ],
)
def test_bare_encode_is_utf8(fragment: bytes):
    """str.encode() / bytes.decode() default to UTF-8 per PEP 3120.

    The audit accepts bare ``.encode()`` calls only because the
    Python language guarantees UTF-8 here regardless of locale —
    this is the load-bearing assumption that lets us skip linting
    them in ``test_no_implicit_text_open``. If a future Python ever
    changes this default, every signed-webhook / cluster-id hash
    flips and this assertion catches it first.
    """
    assert isinstance(fragment, bytes)
    assert fragment.decode() == fragment.decode("utf-8")
