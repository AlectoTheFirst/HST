"""PySAML2 temporary files have deterministic, operation-local ownership."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

from hst.app import saml_flow  # Initializes the dependency with its import compatibility filters.
from hst.app.saml_resources import saml_tempfiles


@pytest.fixture
def sigver():
    # Import after saml_flow.
    from saml2 import sigver

    assert saml_flow.Saml2Client is not None
    return sigver


@pytest.mark.parametrize("fail", [False, True])
def test_closes_and_removes_files_even_when_traceback_retains_them(sigver, tmp_path, fail):
    def operation():
        with saml_tempfiles():
            file = sigver.NamedTemporaryFile(dir=tmp_path, suffix=".xml")
            files.append(file)
            file.write(b"signed XML")
            file.flush()
            assert Path(file.name).read_bytes() == b"signed XML"
            if fail:
                raise ValueError("signature verification failed")

    files = []
    if fail:
        with pytest.raises(ValueError, match="signature verification failed") as error:
            operation()
        assert error.value.__traceback__ is not None
    else:
        operation()
    assert all(file.closed and not Path(file.name).exists() for file in files)


def test_nested_scopes_do_not_close_outer_files(sigver, tmp_path):
    with saml_tempfiles():
        outer = sigver.NamedTemporaryFile(dir=tmp_path)
        with saml_tempfiles():
            inner = sigver.NamedTemporaryFile(dir=tmp_path)
        assert inner.closed
        assert not outer.closed
    assert outer.closed


def test_concurrent_operations_do_not_close_each_others_files(sigver, tmp_path):
    barrier = Barrier(2, timeout=10)

    def first():
        with saml_tempfiles():
            file = sigver.NamedTemporaryFile(dir=tmp_path)
            barrier.wait()
        barrier.wait()
        return file

    def second():
        with saml_tempfiles():
            file = sigver.NamedTemporaryFile(dir=tmp_path)
            barrier.wait()
            barrier.wait()
            assert not file.closed
            assert Path(file.name).exists()
        return file

    with ThreadPoolExecutor(max_workers=2) as pool:
        a, b = pool.submit(first), pool.submit(second)
        files = [a.result(), b.result()]
    assert all(file.closed and not Path(file.name).exists() for file in files)


def test_unscoped_files_remain_caller_owned(sigver, tmp_path):
    with saml_tempfiles():
        pass
    with sigver.NamedTemporaryFile(dir=tmp_path) as file:
        with saml_tempfiles():
            pass
        assert not file.closed


def test_preserves_explicit_keep_file_option(sigver, tmp_path):
    with saml_tempfiles():
        file = sigver.NamedTemporaryFile(dir=tmp_path, delete=False)
    assert file.closed
    assert Path(file.name).exists()
