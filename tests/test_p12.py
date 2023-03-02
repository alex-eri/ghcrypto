from ghcrypto import pkey, p12, digest
import pytest

from .test_pkey import signature

def test_p12_parse():
    p = p12.PKCS12.from_bytes(open('tests/selfsigned.p12','rb').read())
    k,cr,ca = p.parse(b'testpassword')


def test_combain():
    pd = open('tests/selfsigned.p12','rb').read()
    r = p12.sign_with_p12('this is a test message\n'.encode(),pd,b'testpassword','sha256')
    print(r.hex())
    assert r.hex() == signature