from ghcrypto import pkey, digest
import pytest


def test_pkey_gost():
    try:
        k = pkey.generate_key_pair("gost2012_256", params=[(b"paramset", b"A")])
    except Exception as e:
        pytest.skip('Not supported', e)
    d = digest.new('md_gost12_256')
    d.update('this is a test message\n'.encode())
    c = pkey.PkeyCtx(pkey=k)
    s = c.sign(d)
    k.verify(s, d.digest())


def test_pkey():
    k = pkey.generate_key_pair("rsa")
    d = digest.new('sha256')
    d.update('this is a test message\n'.encode())
    c = pkey.PkeyCtx(pkey=k)
    s = c.sign(d)
    k.verify(s, d.digest())

signature = '8530b7d78452cd3b81c1c07ffcb528b588b05197f0ddffd17357554126b0299939208aa17f3c45acd497e54a2d6ec3e85269fa0e16bf1ba2e78a1a3e73c67836f69c3895d12d1ba0dc16bdf5dbace45903f7fe78b156ce68dc8e6111a10a97abe45f1a8a6a7e75a8beb6e212edc671f987f5f9af518062a3f659af2e21a16cfaf2b8288768d3691e9346986360e0fae0d777cd4f987cd8b53de9799c2fccd6e422331ca16ad64448b7066d6197f604f952392626657901077f5c9c5239273983ad5545faa5686256af1f63be4376076a80ff730fdc667da5bf3a18915eaa651d2bd7819ca7fc4d131ccf256570878f5770f0c44c92d6905a2cf01ace917c5713'
digesthex  = '3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb'

def test_load_crt():
    f = open('tests/selfsigned.crt','rb')
    crt = pkey.X509.from_pem_bytes(f.read())
    k = crt.get_pubkey()
    k.verify(bytes.fromhex(signature),bytes.fromhex(digesthex))

def test_load_key():
    d = digest.new('md_gost12_256')
    f = open('tests/selfsigned.key','rb')
    k = pkey.Pkey.private_from_pem_bytes(f.read(), password=b'')
    c = pkey.PkeyCtx(pkey=k)
    s = c.sign(digesthex)
    assert s.hex() == signature

