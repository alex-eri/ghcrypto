from ghcrypto import pkey, digest
import pytest


def test_pkey_gost():
    try:
        k = pkey.generate_key_pair(
            "gost2012_256", params=[(b"paramset", b"A")])
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


# signature = ('8530b7d78452cd3b81c1c07ffcb528b588b05197f0ddffd17357554126b02999'
#              '39208aa17f3c45acd497e54a2d6ec3e85269fa0e16bf1ba2e78a1a3e73c67836'
#              'f69c3895d12d1ba0dc16bdf5dbace45903f7fe78b156ce68dc8e6111a10a97ab'
#              'e45f1a8a6a7e75a8beb6e212edc671f987f5f9af518062a3f659af2e21a16cfa'
#              'f2b8288768d3691e9346986360e0fae0d777cd4f987cd8b53de9799c2fccd6e4'
#              '22331ca16ad64448b7066d6197f604f952392626657901077f5c9c5239273983'
#              'ad5545faa5686256af1f63be4376076a80ff730fdc667da5bf3a18915eaa651d'
#              '2bd7819ca7fc4d131ccf256570878f5770f0c44c92d6905a2cf01ace917c5713')

# digesthex = '3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb'


signature = ('a79a87263a81f49182454a14585836bd6c0c1c8cdded938e3592df646e0e6056'
             'e582bf0098cf2b649fceeeaf7f772a68a8dc378057984e0fdd1a48aa2dd6c3b8'
             '0745b509acae39dc2e0c851cd7cec241e32e74c2e3715cc7fc72ffe0c9166874'
             'a1a1d17d0c7b81a1887a9f0144cf8d6126d0953017d26ca174d8d4e5e01791f7'
             'ddea3c6a1b77dbea756d913b183d5e6e1c7ad308b3eb9b577727f7ecdc9f2169'
             'c855cca442c66f3ffb65fcfa76e1ff482f742c97c639d3304116b64b88854aec'
             '184d10d22c234ec13d391fd687b96ca46fcfee65af0f1d7d27ab48f9ee5a7303'
             'a7978648ac7e8816855940c0137de8d51618c249f9bb3ee856f4ea18d7ae1cdb')

digesthex =  '934c62a5ec3534eba9fba9a19920094a0f4db256ed1d8ee386a77d0ac48a21b3'

def test_load_crt():
    f = open('tests/selfsigned.crt', 'rb')
    crt = pkey.X509.from_pem_bytes(f.read())
    k = crt.get_pubkey()
    k.verify(bytes.fromhex(signature), bytes.fromhex(digesthex))


def test_load_key():
    f = open('tests/selfsigned.key', 'rb')
    k = pkey.Pkey.private_from_pem_bytes(f.read(), password=b'')
    c = pkey.PkeyCtx(pkey=k)
    s = c.sign(digesthex)
    assert s.hex() == signature
