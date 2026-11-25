"""A Fernet token read a piece at a time (app/crypto.py `TokenReader`).

The raw store opens a sealed payload through this reader so that the token
and its plaintext are never held whole. The plaintext must be exactly what
`decrypt` returns, however the file is read, bytes outside the base64
alphabet skipped as `decrypt` skips them, and a token `decrypt` refuses must
be refused the same way, before any of it is decrypted. The reader reads the
file twice, so it must also refuse a file that changes between its first pass
and its second.
"""

from __future__ import annotations

import base64
import gc
import hashlib
import io
import random
import tracemalloc
from pathlib import Path

import pytest
from cryptography.fernet import Fernet, InvalidToken

from hst.app import crypto
from hst.app.crypto import SecretKeyError, TokenReader, TokenWriter, decrypt, encrypt

KEY = Fernet.generate_key().decode()

# Lengths around every boundary the reader handles: an AES block (16), a
# base64 group (3 bytes, 4 characters), the 25-byte header and the 32-byte tag.
EDGE_SIZES = (0, 1, 2, 3, 4, 15, 16, 17, 31, 32, 33, 47, 48, 49, 64, 65, 70_000, 250_000)
# How much of the file each read takes: the smallest allowed, sizes that cut
# the header, the tag and the base64 groups at every offset, and the default.
READ_SIZES = (4, 8, 12, 20, 28, 36, 44, 100, 1 << 20)


def _streamed(data: bytes) -> bytes:
    out = io.BytesIO()
    writer = TokenWriter(KEY, out)
    writer.write(data)
    writer.finish()
    return out.getvalue()


def _read_all(token: bytes, *, read_size: int = 1 << 20, piece: int = -1) -> bytes:
    reader = TokenReader(KEY, io.BytesIO(token), read_size=read_size)
    if piece < 0:
        return reader.read()
    parts = []
    while chunk := reader.read(piece):
        parts.append(chunk)
    return b"".join(parts)


def _flipped(token: bytes, at: int) -> bytes:
    """`token` with the base64 character at `at` changed to another valid one."""
    swapped = b"B" if token[at : at + 1] == b"A" else b"A"
    return token[:at] + swapped + token[at + 1 :]


# --- the plaintext ----------------------------------------------------------------------


def test_the_plaintext_is_what_decrypt_returns_however_the_file_is_read():
    rng = random.Random(20260927)
    for size in EDGE_SIZES:
        data = rng.randbytes(size)
        for token in (encrypt(KEY, data), _streamed(data)):
            assert decrypt(KEY, token) == data
            # the smallest reads of the largest token add nothing but time
            small = size <= 70_000
            for read_size in READ_SIZES if small else READ_SIZES[-2:]:
                assert _read_all(token, read_size=read_size) == data, (size, read_size)
            for piece in (1, 7, 16, 4096):
                read_size = 12 if small else 1 << 20
                assert _read_all(token, read_size=read_size, piece=piece) == data, (size, piece)


def test_readinto_fills_the_buffer_it_is_given():
    data = random.Random(4).randbytes(10_000)
    reader = TokenReader(KEY, io.BytesIO(encrypt(KEY, data)), read_size=64)
    buffer = bytearray(333)
    out = bytearray()
    while n := reader.readinto(buffer):
        out += buffer[:n]
    assert bytes(out) == data
    assert reader.readinto(buffer) == 0


def test_the_token_is_read_from_the_current_position_of_the_file():
    data = b"payload" * 100
    fh = io.BytesIO(b"prefix-not-a-token" + encrypt(KEY, data))
    fh.seek(len(b"prefix-not-a-token"))
    assert TokenReader(KEY, fh, read_size=8).read() == data


def test_a_read_size_that_is_not_whole_base64_groups_is_refused():
    token = encrypt(KEY, b"x")
    for read_size in (0, 1, 2, 3, 5, 6, 1023):
        with pytest.raises(ValueError, match="multiple of 4"):
            TokenReader(KEY, io.BytesIO(token), read_size=read_size)


# --- failures ---------------------------------------------------------------------------


def _refusals(token: bytes) -> tuple[SecretKeyError, SecretKeyError]:
    with pytest.raises(SecretKeyError) as from_decrypt:
        decrypt(KEY, token)
    with pytest.raises(SecretKeyError) as from_reader:
        _read_all(token, read_size=8)
    return from_decrypt.value, from_reader.value


def test_a_tampered_token_is_refused_as_decrypt_refuses_it():
    data = random.Random(3).randbytes(5_000)
    for token in (encrypt(KEY, data), _streamed(data)):
        # the version byte, the timestamp, the IV, the ciphertext, the tag
        for at in (0, 3, 20, 40, len(token) // 2, len(token) - 30, len(token) - 5):
            from_decrypt, from_reader = _refusals(_flipped(token, at))
            assert str(from_reader) == str(from_decrypt) == crypto.GUIDANCE
            assert type(from_reader.__cause__) is type(from_decrypt.__cause__) is InvalidToken


def test_a_truncated_or_malformed_token_is_refused_as_decrypt_refuses_it():
    token = encrypt(KEY, b"x" * 1000)
    unfinished = io.BytesIO()
    TokenWriter(KEY, unfinished).write(bytes(10_000))
    for bad in (
        b"",
        token[:4],
        token[:60],
        token[:-4],
        token[:-1],  # a base64 group cut short
        token[:-2] + b"==",  # the padding moved into the data
        b"=" + token[1:],
        token[:10] + b"*" + token[11:],  # a character replaced by one outside the alphabet
        unfinished.getvalue(),
    ):
        from_decrypt, from_reader = _refusals(bad)
        assert str(from_reader) == str(from_decrypt) == crypto.GUIDANCE
        assert type(from_reader.__cause__) is InvalidToken


def _wrapped(token: bytes, width: int, newline: bytes) -> bytes:
    return newline.join(token[i : i + width] for i in range(0, len(token), width)) + newline


def test_bytes_outside_the_base64_alphabet_are_skipped_as_decrypt_skips_them():
    """A token that a copy as text ended with a line break, or wrapped at 76
    columns, reads as `decrypt` reads it, however the reads fall. The three
    sizes give a token ending in two, one and no padding characters."""
    rng = random.Random(12)
    for size in (5_007, 5_023, 4_991):
        data = rng.randbytes(size)
        token = encrypt(KEY, data)
        for text in (
            token + b"\n",
            token + b"\r\n",
            b" " + token + b"\t\n",
            _wrapped(token, 76, b"\n"),
            _wrapped(token, 76, b"\r\n"),
            _wrapped(token, 64, b"\n"),
            token[:100] + b"\x00\x80\xff" + token[100:],
        ):
            assert decrypt(KEY, text) == data
            for read_size in READ_SIZES:
                assert _read_all(text, read_size=read_size) == data, (size, text[-6:], read_size)


def test_padding_ends_the_token_wherever_the_reads_fall():
    """A padding character is taken only at the end of the token; `decrypt`
    reads one elsewhere by rules that differ between Python versions. The
    reader refuses characters after it, including when a read ends right
    after the padding and what follows decodes to bytes that authenticate:
    the token's own bytes, encoded in two parts."""
    token = encrypt(KEY, b"x" * 100)
    assert token.endswith(b"==")
    raw = base64.urlsafe_b64decode(token)
    head = base64.urlsafe_b64encode(raw[:40])
    assert head.endswith(b"==") and len(head) % 4 == 0
    split = head + base64.urlsafe_b64encode(raw[40:])
    for bad in (token + b"AAAA", token + b"\nAAAA", split):
        for read_size in (4, 8, len(head), 1 << 20):
            with pytest.raises(SecretKeyError) as raised:
                _read_all(bad, read_size=read_size)
            assert type(raised.value.__cause__) is InvalidToken


def test_a_token_under_another_key_is_refused():
    token = encrypt(Fernet.generate_key().decode(), b"payload")
    with pytest.raises(SecretKeyError) as raised:
        TokenReader(KEY, io.BytesIO(token))
    assert type(raised.value.__cause__) is InvalidToken


@pytest.mark.parametrize(
    "key",
    ["", "not-a-key", "☃" * 44],
    ids=["empty", "not-base64", "non-ascii"],
)
def test_a_key_decrypt_refuses_is_refused_the_same_way_before_the_file_is_read(key):
    with pytest.raises(SecretKeyError) as from_decrypt:
        decrypt(key, encrypt(KEY, b"x"))
    fh = io.BytesIO(encrypt(KEY, b"x"))
    with pytest.raises(SecretKeyError) as from_reader:
        TokenReader(key, fh)
    assert str(from_reader.value) == str(from_decrypt.value) == crypto.GUIDANCE
    assert fh.tell() == 0


def test_nothing_is_decrypted_before_the_whole_token_authenticates(monkeypatch):
    """The first pass checks the tag over the whole file; a token whose last
    byte is wrong is refused when the reader is created, and no cipher was
    set up for it."""
    ciphers: list[object] = []
    real = crypto.Cipher

    def recording(*args, **kwargs):
        ciphers.append(args)
        return real(*args, **kwargs)

    monkeypatch.setattr(crypto, "Cipher", recording)
    token = encrypt(KEY, random.Random(8).randbytes(100_000))
    with pytest.raises(SecretKeyError):
        TokenReader(KEY, io.BytesIO(_flipped(token, len(token) - 3)), read_size=64)
    assert ciphers == []

    assert _read_all(token, read_size=64) == decrypt(KEY, token)
    assert len(ciphers) == 1


class _Changing:
    """A file whose bytes are `first` until it is sought, and `second` after,
    as a file rewritten between the reader's two passes."""

    def __init__(self, first: bytes, second: bytes) -> None:
        self._files = [io.BytesIO(first), io.BytesIO(second)]

    def tell(self) -> int:
        return self._files[0].tell()

    def read(self, size: int = -1) -> bytes:
        return self._files[0].read(size)

    def seek(self, pos: int, whence: int = 0) -> int:
        if len(self._files) > 1:
            self._files.pop(0)
        return self._files[0].seek(pos, whence)


def test_a_file_that_changes_between_the_passes_is_refused_before_its_end():
    """The second pass checks what it decrypts against the tag the first pass
    authenticated, and the stream never ends for a file that fails it: the
    loop below leaves only by the error, never by an empty read."""
    data = random.Random(11).randbytes(200_000)
    token = encrypt(KEY, data)
    for changed in (_flipped(token, len(token) // 2), token[: len(token) // 2]):
        reader = TokenReader(KEY, _Changing(token, changed), read_size=64)
        with pytest.raises(SecretKeyError) as raised:
            while reader.read(4096):
                pass
        assert type(raised.value.__cause__) is InvalidToken


def test_a_file_that_grows_after_the_first_pass_reads_the_token_it_authenticated():
    """What follows the authenticated length is never read as token."""
    data = b"payload" * 1000
    token = encrypt(KEY, data)
    reader = TokenReader(KEY, _Changing(token, token + b"AAAAAAAA"), read_size=8)
    assert reader.read() == data


# --- memory -----------------------------------------------------------------------------


def test_the_reader_holds_one_read_not_the_token(tmp_path: Path):
    piece = 64 * 1024
    pieces = 256  # 16 MiB of plaintext
    path = tmp_path / "token"
    with path.open("wb") as fh:
        writer = TokenWriter(KEY, fh)
        for i in range(pieces):
            writer.write(bytes([i]) * piece)
        writer.finish()

    gc.collect()
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        before = tracemalloc.get_traced_memory()[0]
        digest = hashlib.sha256()
        with path.open("rb") as fh:
            reader = TokenReader(KEY, fh)
            while chunk := reader.read(piece):
                digest.update(chunk)
        peak = tracemalloc.get_traced_memory()[1] - before
    finally:
        tracemalloc.stop()
    expected = hashlib.sha256(b"".join(bytes([i]) * piece for i in range(pieces)))
    assert digest.hexdigest() == expected.hexdigest()
    total = piece * pieces
    assert peak <= 8 << 20, f"peak {peak / 1e6:.1f} MB over {total / 1e6:.0f} MB of plaintext"
