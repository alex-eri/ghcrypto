import pytest
import binascii

from ghcrypto import digest

def test_digest():
    digest_type = digest.DigestType.from_name('SHA512')
    sha512 = digest.Digest(digest_type)
    sha512.update(b"test")
    assert not sha512.finalized
    digest_ = sha512.digest()
    digest_str = binascii.hexlify(digest_).decode('ascii')
    assert len(digest_) == 64
    assert digest_str == (
        "ee26b0dd4af7e749aa1a8ee3c10ae992"
        "3f618980772e473f8819a5d4940e0db2"
        "7ac185f8a0e1d5f84f88bc887fd67b14"
        "3732c304cc5fa9ad8e6f57f50028a8ff"
    )

def test_digest_gost():
    try:
        digest_type = digest.DigestType.from_name('md_gost12_256')
    except digest.DigestError as e:
        pytest.skip(e)
    sha512 = digest.Digest(digest_type)
    sha512.update(b"test")
    assert not sha512.finalized
    digest_ = sha512.digest()
    digest_str = binascii.hexlify(digest_).decode('ascii')
    assert len(digest_) == 32
    assert digest_str == (
        "12a50838191b5504f1e5f2fd078714cf6b592b9d29af99d0b10d8d02881c3857"
    )