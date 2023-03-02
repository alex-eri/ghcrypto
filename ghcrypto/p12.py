import ctypes

from .lib import libcrypto
from .bio import BIO

from .digest import Digest

from .pkey import Pkey, X509

from ctypes import c_void_p, c_long, POINTER, c_int, c_char_p, c_size_t, c_ubyte, byref


class PKCS12(ctypes.Structure):

    @classmethod
    def from_bytes(cls, data):
        bp = BIO.from_bytes(data)
        r = libcrypto.d2i_PKCS12_bio(bp, None)
        assert r, "d2i_PKCS12_bio failed"
        return r.contents

    def parse(self, password):
        key = POINTER(Pkey)()
        cert = POINTER(X509)()
        ca = POINTER(X509)()
        c_password = ctypes.create_string_buffer(password)
        r = libcrypto.PKCS12_parse(self,c_password,byref(key),byref(cert), ca)
        assert r == 1, 'PKCS12_parse error'
        return key.contents, cert.contents, ca and ca.contents


def sign_with_p12(data:bytes, p12data:bytes, password:bytes, digestalgo:str):
    p = PKCS12.from_bytes(p12data)
    k,crt,ca = p.parse(password)
    ctx = k.new_ctx()
    d = Digest.from_name(digestalgo)
    d.update(data)
    print(d.digest().hex())
    s = ctx.sign(d)
    return s



libcrypto.d2i_PKCS12_bio.argtypes = (POINTER(BIO), POINTER(POINTER(PKCS12)))
libcrypto.d2i_PKCS12_bio.restype = POINTER(PKCS12)
libcrypto.PKCS12_parse.argtypes = (POINTER(PKCS12),c_char_p, POINTER(POINTER(Pkey)), POINTER(POINTER(X509)), POINTER(POINTER(X509)))