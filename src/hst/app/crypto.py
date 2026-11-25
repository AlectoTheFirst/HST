"""Encryption at rest with an envelope scheme for source credentials and raw snapshots."""

from __future__ import annotations

import base64
import binascii
import io
import json
import os
import re
import secrets as _secrets
import time
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, NoReturn

from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

if TYPE_CHECKING:
    from _typeshed import WriteableBuffer

    from hst.core.config import Settings

DEK_FILENAME = "dek.wrapped"
MIN_KEK_BYTES = 32

GUIDANCE = (
    "HST_SECRET_KEY is missing or wrong: the key is read from HST_SECRET_KEY "
    "or HST_SECRET_KEY_FILE and is any value of at least 32 bytes (`hst "
    "secret-key` generates one). The sealed credentials and raw snapshots open only "
    "under the key that wrapped dek.wrapped; without that key they are unrecoverable, "
    "and a new dek.wrapped under a new key holds none of them."
)


class SecretKeyError(Exception):
    pass


def generate_key() -> str:
    """Generate a KEK of 43 urlsafe characters with 256 bits of entropy."""
    return _secrets.token_urlsafe(32)


def _fernet_for_kek(raw: bytes) -> Fernet:
    if len(raw) < MIN_KEK_BYTES:
        raise SecretKeyError(
            f"secret key is {len(raw)} bytes; at least {MIN_KEK_BYTES} are required; " + GUIDANCE
        )
    derived = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=b"strata-reticulum", info=b"dek-wrap-v1"
    ).derive(raw)
    return Fernet(base64.urlsafe_b64encode(derived))


def _kek_bytes(settings: Settings) -> bytes:
    if settings.hst_secret_key_file:
        try:
            raw = Path(settings.hst_secret_key_file).read_bytes().strip()
        except OSError as exc:
            raise SecretKeyError(f"cannot read HST_SECRET_KEY_FILE: {exc}") from exc
    else:
        raw = settings.hst_secret_key.strip().encode()
    if not raw:
        raise SecretKeyError(GUIDANCE)
    return raw


def _unwrap(wrapper: Fernet, path: Path) -> str:
    try:
        return wrapper.decrypt(path.read_bytes()).decode()
    except InvalidToken as exc:
        raise SecretKeyError(GUIDANCE) from exc


def unwrap_dek(wrapped: bytes, operator_key: bytes) -> str:
    """Authenticate and unwrap captured DEK bytes under the KEK `operator_key`."""
    try:
        return _fernet_for_kek(operator_key).decrypt(wrapped).decode()
    except (InvalidToken, UnicodeError) as exc:
        raise SecretKeyError(GUIDANCE) from exc


def dek(settings: Settings) -> str:
    """The data-encryption key, creating HST_DATA_DIR/dek.wrapped on first use.

    O_EXCL plus a re-read on EEXIST makes concurrent first use safe for processes
    sharing one data directory (replicas on a shared volume, CLI beside the app).
    """
    wrapper = _fernet_for_kek(_kek_bytes(settings))
    path = settings.hst_data_dir / DEK_FILENAME
    if path.is_file():
        return _unwrap(wrapper, path)
    new = Fernet.generate_key()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return _unwrap(wrapper, path)
    with os.fdopen(fd, "wb") as fh:
        fh.write(wrapper.encrypt(new))
    return new.decode()


def rewrap_dek(settings: Settings, new_kek: str) -> None:
    """Re-wrap the DEK under a new KEK for a key rotation. Stored data is not rewritten."""
    current = dek(settings)
    token = _fernet_for_kek(new_kek.strip().encode()).encrypt(current.encode())
    path = settings.hst_data_dir / DEK_FILENAME
    tmp = path.with_suffix(".tmp")
    with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as fh:
        fh.write(token)
    tmp.replace(path)


def install_dek(settings: Settings, key: str) -> None:
    """Write the Fernet key `key`, wrapped under the KEK, as the DEK of a data
    directory that has none. An existing dek.wrapped raises FileExistsError."""
    _fernet_keys(key)
    token = _fernet_for_kek(_kek_bytes(settings)).encrypt(key.encode())
    path = settings.hst_data_dir / DEK_FILENAME
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as fh:
        fh.write(token)


def encrypt(key: str, blob: bytes) -> bytes:
    """Encrypt raw bytes under the DEK."""
    try:
        f = Fernet(key.encode())
    except (ValueError, TypeError) as exc:
        raise SecretKeyError(GUIDANCE) from exc
    return f.encrypt(blob)


def decrypt(key: str, token: bytes) -> bytes:
    """Decrypt bytes sealed under the DEK."""
    try:
        return Fernet(key.encode()).decrypt(token)
    except (ValueError, TypeError, InvalidToken) as exc:
        raise SecretKeyError(GUIDANCE) from exc


# The version byte a Fernet token starts with (https://github.com/fernet/spec).
_FERNET_VERSION = b"\x80"


def _fernet_keys(key: str) -> tuple[bytes, bytes]:
    """Return the signing key and the encryption key of a DEK.

    The Fernet spec splits the url-safe base64 decoding of the DEK into the
    first 16 bytes and the last 16 bytes. `Fernet` checks the key first. A
    key that `encrypt` refuses raises the same SecretKeyError here."""
    try:
        Fernet(key.encode())
    except (ValueError, TypeError) as exc:
        raise SecretKeyError(GUIDANCE) from exc
    raw = base64.urlsafe_b64decode(key.encode())
    return raw[:16], raw[16:]


PACKAGE_ID = re.compile(r"[0-9a-f]{32}")


def package_key(key: str, package_id: str) -> str:
    """Derive the Fernet key of the assessment package `package_id` from the
    DEK `key`. The derivation is HKDF-SHA256 over the 32 bytes of the DEK.
    `info` holds a fixed label and the package identity."""
    if not PACKAGE_ID.fullmatch(package_id):
        raise ValueError("A package identity is 32 lowercase hexadecimal characters.")
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"strata-reticulum",
        info=b"assessment-package-v1:" + package_id.encode(),
    ).derive(b"".join(_fernet_keys(key)))
    return base64.urlsafe_b64encode(derived).decode()


class TokenWriter:
    """Writes one Fernet token under the DEK to a binary file, encrypting the
    plaintext a piece at a time.

    The writer holds only the piece it is given. `write` pads and encrypts it
    (AES-128-CBC, PKCS7), adds the ciphertext to the HMAC-SHA256 and writes it
    as url-safe base64, carrying the fewer than 3 bytes that do not yet fill a
    base64 group to the next piece. The header (version, timestamp, IV) is
    written when the writer is created, and `finish` writes the last block, the
    HMAC and the carried bytes.

    Once `finish` returns, the file holds exactly the token `encrypt` returns
    for the concatenated pieces at the same time and IV, and `decrypt` reads
    it. A writer that is abandoned before `finish` leaves a truncated token
    that `decrypt` refuses. The caller removes the file.
    """

    def __init__(self, key: str, fh: BinaryIO) -> None:
        signing, encryption = _fernet_keys(key)
        iv = os.urandom(16)
        self._fh = fh
        self._carry = b""
        self._mac = HMAC(signing, hashes.SHA256())
        self._padder = padding.PKCS7(algorithms.AES.block_size).padder()
        self._encryptor = Cipher(algorithms.AES(encryption), modes.CBC(iv)).encryptor()
        self._sign(_FERNET_VERSION + int(time.time()).to_bytes(8, "big") + iv)

    def write(self, data: bytes) -> None:
        """Encrypt one piece of plaintext and write what it completes."""
        self._sign(self._encryptor.update(self._padder.update(data)))

    def finish(self) -> None:
        """Write the padded last block and the HMAC, completing the token."""
        self._sign(self._encryptor.update(self._padder.finalize()) + self._encryptor.finalize())
        self._emit(self._mac.finalize())
        if self._carry:
            self._fh.write(base64.urlsafe_b64encode(self._carry))
            self._carry = b""

    def _sign(self, data: bytes) -> None:
        self._mac.update(data)
        self._emit(data)

    def _emit(self, data: bytes) -> None:
        """Write the carried bytes and `data` as base64, whole 3-byte groups
        only, and carry the rest."""
        if self._carry:
            data = self._carry + data
        cut = len(data) - len(data) % 3
        self._carry = data[cut:]
        if cut:
            self._fh.write(base64.urlsafe_b64encode(memoryview(data)[:cut]))


# The count of bytes that `TokenReader` reads from a token file at a time. It
# is a multiple of 4. A file that holds the token alone decodes one read at a
# time with no character left for the next read.
_READ_SIZE = 1 << 20
# The size of the HMAC-SHA256 tag that ends a Fernet token, and the size of
# the header before its ciphertext. The header holds the version byte, the
# 8-byte timestamp and the 16-byte IV.
_TAG_BYTES = 32
_HEADER_BYTES = 25
_URLSAFE_TO_STANDARD = bytes.maketrans(b"-_", b"+/")
# The bytes that `decrypt` skips in a token. These are all bytes outside the
# url-safe base64 alphabet, the standard base64 alphabet and the padding
# character.
_NOT_BASE64 = bytes(
    sorted(set(range(256)) - set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_+/="))
)


def _refuse() -> NoReturn:
    """Raise what `decrypt` raises for a token Fernet refuses."""
    raise SecretKeyError(GUIDANCE) from InvalidToken()


class TokenReader(io.RawIOBase):
    """Reads the plaintext of one Fernet token under the DEK from a binary
    file, a piece at a time.

    The reader reads the file twice and holds one read of it at a time. The
    first pass, when the reader is created, decodes the url-safe base64 and
    checks the version byte and the HMAC-SHA256 over everything before the tag.
    A token that `decrypt` refuses is refused here with the same
    SecretKeyError before any of it is decrypted. The second pass, as the
    plaintext is read, decrypts the ciphertext (AES-128-CBC, PKCS7) and
    computes the HMAC again. The stream reaches its end only once that HMAC
    matches the tag that the first pass checked. A file that changes between
    the passes raises before the end.

    `fh` must be seekable and is read from its current position. The
    plaintext is exactly what `decrypt` returns for the same token. Bytes
    outside the base64 alphabet, such as the line breaks of a file that was
    wrapped or copied as text, are skipped, as `decrypt` skips them. A
    padding character is taken only at the end of the token, where `encrypt`
    and `TokenWriter` put it.
    """

    def __init__(self, key: str, fh: BinaryIO, *, read_size: int = _READ_SIZE) -> None:
        super().__init__()
        if read_size < 4 or read_size % 4:
            raise ValueError(f"read_size must be a positive multiple of 4, not {read_size}")
        signing, encryption = _fernet_keys(key)
        start = fh.tell()
        tag, length = _authenticate(_token_bytes(fh, read_size), signing)
        fh.seek(start)
        self._pieces = _plaintext(_token_bytes(fh, read_size), signing, encryption, tag, length)
        self._piece = memoryview(b"")

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: WriteableBuffer) -> int:
        while not self._piece:
            piece = next(self._pieces, None)
            if piece is None:
                return 0
            self._piece = memoryview(piece)
        with memoryview(buffer) as view, view.cast("B") as target:
            n = min(len(target), len(self._piece))
            target[:n] = self._piece[:n]
        self._piece = self._piece[n:]
        return n


def _token_bytes(fh: BinaryIO, read_size: int) -> Iterator[bytes]:
    """The bytes of the url-safe base64 token in `fh`, from its current
    position to its end, decoded a read at a time.

    The characters are grouped in fours as the bytes `decrypt` skips are left
    out, and the characters of an unfinished group are carried to the next read.
    A read is decoded as it is, and again without those bytes when that fails. A
    group that ends in padding ends the token, and a character after it is
    refused.
    """
    held = b""
    ended = False
    while chunk := fh.read(read_size):
        chunk = chunk.translate(_URLSAFE_TO_STANDARD)
        if held:
            chunk = held + chunk
        cut = len(chunk) - len(chunk) % 4
        try:
            data = binascii.a2b_base64(chunk[:cut], strict_mode=True)
        except binascii.Error:
            chunk = chunk.translate(None, _NOT_BASE64)
            cut = len(chunk) - len(chunk) % 4
            try:
                data = binascii.a2b_base64(chunk[:cut], strict_mode=True)
            except binascii.Error:
                _refuse()
        held = chunk[cut:].translate(None, _NOT_BASE64)
        if ended and (data or held):
            _refuse()
        if data:
            ended = chunk[cut - 1] == ord("=")
            yield data
    if held:
        _refuse()


def _authenticate(token: Iterator[bytes], signing: bytes) -> tuple[bytes, int]:
    """Check a token's version byte and its HMAC over everything before the
    tag, as Fernet checks them, and return the tag and the token's length."""
    mac = HMAC(signing, hashes.SHA256())
    version = None
    length = 0
    # `tail` holds the last `_TAG_BYTES` bytes read. At the end of the token they are the tag.
    tail = b""
    for data in token:
        if version is None:
            version = data[0]
        length += len(data)
        if len(data) >= _TAG_BYTES:
            mac.update(tail)
            mac.update(memoryview(data)[:-_TAG_BYTES])
            tail = data[-_TAG_BYTES:]
        else:
            joined = tail + data
            mac.update(joined[:-_TAG_BYTES])
            tail = joined[-_TAG_BYTES:]
    if version != _FERNET_VERSION[0] or length < 9:
        _refuse()
    try:
        mac.verify(tail)
    except InvalidSignature:
        _refuse()
    return tail, length


def _plaintext(
    token: Iterator[bytes], signing: bytes, encryption: bytes, tag: bytes, length: int
) -> Iterator[bytes]:
    """Yield the plaintext of a token that `_authenticate` accepted, a piece
    at a time. The HMAC of the decrypted bytes is checked against `tag` before
    the last piece. The unpadding holds the last piece back until then."""
    mac = HMAC(signing, hashes.SHA256())
    signed = length - _TAG_BYTES
    seen = 0
    header = b""
    decryptor = None
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    for data in token:
        if seen + len(data) > signed:
            data = data[: signed - seen]
        seen += len(data)
        mac.update(data)
        if decryptor is None:
            header += data
            if len(header) < _HEADER_BYTES:
                continue
            decryptor = Cipher(algorithms.AES(encryption), modes.CBC(header[9:_HEADER_BYTES])).decryptor()
            data, header = header[_HEADER_BYTES:], b""
        if data and (piece := unpadder.update(decryptor.update(data))):
            yield piece
        if seen == signed:
            break
    if seen < signed or decryptor is None:
        _refuse()
    try:
        mac.verify(tag)
    except InvalidSignature:
        _refuse()
    try:
        last = unpadder.update(decryptor.finalize()) + unpadder.finalize()
    except ValueError:
        _refuse()
    if last:
        yield last


def encrypt_secrets(key: str, secrets: dict[str, str]) -> bytes:
    return encrypt(key, json.dumps(secrets).encode())


def decrypt_secrets(key: str, blob: bytes) -> dict[str, str]:
    if not blob:
        return {}
    return json.loads(decrypt(key, blob))
