"""A Fernet token written a piece at a time (app/crypto.py `TokenWriter`).

The raw store seals a payload through this writer so that neither the
compressed payload nor its token is ever held whole. Every reader opens the
file with `decrypt`, which takes one Fernet token, so the streamed token is
byte for byte what `Fernet` builds for the same plaintext, time and IV,
however the plaintext is split. Its key handling and its failures are those of
`encrypt` and `decrypt`.
"""

from __future__ import annotations

import base64
import gc
import io
import itertools
import random
import tracemalloc

import pytest
from cryptography.fernet import Fernet, InvalidToken

from hst.app import crypto
from hst.app.crypto import SecretKeyError, TokenWriter, decrypt, encrypt

KEY = Fernet.generate_key().decode()
NOW = 1_700_000_123
IV = bytes(range(16))

# Lengths around every boundary the writer handles: an AES block (16), a base64
# group (3), and both at once (48), beside a random spread up to 70 kB.
EDGE_SIZES = (0, 1, 2, 3, 4, 15, 16, 17, 31, 32, 33, 47, 48, 49, 64, 65, 70_000)


def _streamed(key: str, pieces: list[bytes]) -> bytes:
    out = io.BytesIO()
    writer = TokenWriter(key, out)
    for piece in pieces:
        writer.write(piece)
    writer.finish()
    return out.getvalue()


def _split(data: bytes, rng: random.Random) -> list[bytes]:
    """`data` cut at random points, empty pieces included."""
    cuts = sorted(rng.randint(0, len(data)) for _ in range(rng.randint(0, 12)))
    bounds = [0, *cuts, len(data)]
    return [data[a:b] for a, b in itertools.pairwise(bounds)]


@pytest.fixture
def fixed_time_and_iv(monkeypatch):
    """The token's time and IV, as `Fernet._encrypt_from_parts` takes them."""

    def urandom(n: int) -> bytes:
        assert n == 16
        return IV

    monkeypatch.setattr(crypto.time, "time", lambda: NOW + 0.75)
    monkeypatch.setattr(crypto.os, "urandom", urandom)


# --- the token --------------------------------------------------------------------------


def test_the_streamed_token_is_the_fernet_token_however_the_plaintext_is_split(fixed_time_and_iv):
    rng = random.Random(20260926)
    reference = Fernet(KEY.encode())
    sizes = [*EDGE_SIZES, *(rng.randint(0, 70_000) for _ in range(40))]
    for size in sizes:
        data = rng.randbytes(size)
        expected = reference._encrypt_from_parts(data, NOW, IV)
        for _ in range(3):
            pieces = _split(data, rng)
            assert _streamed(KEY, pieces) == expected, f"{size} bytes in {len(pieces)} pieces"
        head = data[:100]
        byte_at_a_time = [head[i : i + 1] for i in range(len(head))]
        assert _streamed(KEY, byte_at_a_time) == reference._encrypt_from_parts(head, NOW, IV)


def test_the_token_carries_the_current_time_and_a_fresh_iv():
    first, second = _streamed(KEY, [b"same"]), _streamed(KEY, [b"same"])
    assert first != second
    raw = [base64.urlsafe_b64decode(token) for token in (first, second)]
    assert raw[0][9:25] != raw[1][9:25]
    for token in (first, second):
        assert Fernet(KEY.encode()).extract_timestamp(token) == pytest.approx(crypto.time.time(), abs=5)


def test_decrypt_reads_every_streamed_token():
    rng = random.Random(7)
    for size in (*EDGE_SIZES, 250_000):
        data = rng.randbytes(size)
        assert decrypt(KEY, _streamed(KEY, _split(data, rng))) == data


def test_the_streamed_token_is_written_a_piece_at_a_time():
    """What each `write` completes is in the file before the next piece
    arrives: the base64 of every whole 3-byte group so far, the header and the
    ciphertext of every full block."""
    out = io.BytesIO()
    writer = TokenWriter(KEY, out)
    assert len(out.getvalue()) == 32  # the 25-byte header: 8 whole groups, 1 byte carried
    writer.write(bytes(1000))
    assert len(out.getvalue()) == 4 * ((25 + 992) // 3)  # 62 full blocks, 8 bytes held for padding
    writer.finish()
    assert len(out.getvalue()) == len(encrypt(KEY, bytes(1000)))


def test_the_writer_holds_one_piece_not_the_plaintext(tmp_path):
    piece = 64 * 1024
    pieces = 256  # 16 MiB in all
    gc.collect()
    tracemalloc.start()
    try:
        with (tmp_path / "token").open("wb") as fh:
            tracemalloc.reset_peak()
            before = tracemalloc.get_traced_memory()[0]
            writer = TokenWriter(KEY, fh)
            for _ in range(pieces):
                writer.write(bytes(piece))
            writer.finish()
            peak = tracemalloc.get_traced_memory()[1] - before
    finally:
        tracemalloc.stop()
    assert peak <= 16 * piece, f"peak {peak / 1e3:.0f} kB over {piece * pieces / 1e6:.0f} MB of plaintext"
    assert decrypt(KEY, (tmp_path / "token").read_bytes()) == bytes(piece * pieces)


# --- failures ---------------------------------------------------------------------------


def _flipped(token: bytes, at: int) -> bytes:
    """`token` with the base64 character at `at` changed to another valid one,
    which changes one bit of the decoded token."""
    swapped = b"B" if token[at : at + 1] == b"A" else b"A"
    return token[:at] + swapped + token[at + 1 :]


def test_a_tampered_streamed_token_fails_as_a_tampered_fernet_token():
    data = random.Random(3).randbytes(5_000)
    streamed = _streamed(KEY, [data[:1234], data[1234:]])
    fernet = encrypt(KEY, data)
    for at in (5, 30, len(streamed) // 2, len(streamed) - 10):
        with pytest.raises(SecretKeyError) as from_fernet:
            decrypt(KEY, _flipped(fernet, at))
        with pytest.raises(SecretKeyError) as from_stream:
            decrypt(KEY, _flipped(streamed, at))
        assert str(from_stream.value) == str(from_fernet.value) == crypto.GUIDANCE
        assert type(from_stream.value.__cause__) is type(from_fernet.value.__cause__) is InvalidToken


def test_an_unfinished_token_does_not_decrypt():
    out = io.BytesIO()
    writer = TokenWriter(KEY, out)
    writer.write(bytes(10_000))
    with pytest.raises(SecretKeyError) as raised:
        decrypt(KEY, out.getvalue())
    assert isinstance(raised.value.__cause__, InvalidToken)


BAD_KEYS = (
    "",
    "not-a-key",
    base64.urlsafe_b64encode(bytes(31)).decode(),
    base64.urlsafe_b64encode(bytes(33)).decode(),
    # a well-formed key with its last two characters cut; fixed, so every
    # xdist worker collects the same test ids
    base64.urlsafe_b64encode(bytes(range(32))).decode()[:-2],
    "☃" * 44,
)
BAD_KEY_IDS = ("empty", "not-base64", "31-bytes", "33-bytes", "truncated", "non-ascii")


@pytest.mark.parametrize("key", BAD_KEYS, ids=BAD_KEY_IDS)
def test_a_key_encrypt_refuses_is_refused_the_same_way_before_anything_is_written(key):
    with pytest.raises(SecretKeyError) as from_encrypt:
        encrypt(key, b"x")
    out = io.BytesIO()
    with pytest.raises(SecretKeyError) as from_writer:
        TokenWriter(key, out)
    assert str(from_writer.value) == str(from_encrypt.value) == crypto.GUIDANCE
    assert type(from_writer.value.__cause__) is type(from_encrypt.value.__cause__)
    assert out.getvalue() == b""


def test_a_token_under_one_key_does_not_decrypt_under_another():
    with pytest.raises(SecretKeyError):
        decrypt(Fernet.generate_key().decode(), _streamed(KEY, [b"payload"]))
