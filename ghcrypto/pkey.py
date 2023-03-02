import ctypes

from .lib import libcrypto
from .bio import BIO

from .digest import Digest

from ctypes import c_void_p, c_long, POINTER, c_int, c_char_p, c_size_t, c_ubyte



class PEMError(Exception):
    pass


class Error(Exception):
    pass


def bytes_to_ubyte_p(data):
    data_len = len(data)
    return ctypes.cast(c_char_p(data), POINTER(c_ubyte)), data_len


class X509(ctypes.Structure):
    def __new__(cls):
        r = libcrypto.X509_new()
        return ctypes.cast(r, ctypes.POINTER(cls)).contents

    # def to_pem(self):
        # crt_to_pem(crt, &crt_bytes, &crt_size)

    def __del__(self):
        libcrypto.X509_free(self)

    @classmethod
    def from_pem_bytes(cls, data, password=b''):
        bp = BIO.from_bytes(data)

        def password_cb(buf, size, rwflag, userdata):
            c_password = ctypes.create_string_buffer(password)
            ctypes.memmove(ctypes.byref(buf), ctypes.byref(c_password))
            return len(password)
        
        r = libcrypto.PEM_read_bio_X509(bp, None, CBFUNC(password_cb), None)
        if r:
            return r.contents
        raise PEMError('Wrong PEM data')

    def get_pubkey(self):
        r = libcrypto.X509_get_pubkey(self)
        return r.contents


CBFUNC = ctypes.CFUNCTYPE(c_int, c_char_p, c_int, c_int, c_void_p)



libcrypto.PEM_read_bio_X509.argtypes = (
    POINTER(BIO), POINTER(POINTER(X509)), CBFUNC, c_void_p)
libcrypto.PEM_read_bio_X509.restype = POINTER(X509)

libcrypto.X509_free.argtypes = (POINTER(X509),)

class Pkey(ctypes.Structure):
    def verify(self, sig, tbs):
        ctx = PkeyCtx(pkey=self)
        r = ctx.verify(sig, tbs)
        if r < 0:
            raise Error('Verify error', r)
        return r == 1

    @classmethod
    def private_from_pem_bytes(cls, data, password):
        bp = BIO.from_bytes(data)
        def password_cb(buf, size, rwflag, userdata):
            c_password = ctypes.create_string_buffer(password)
            ctypes.memmove(ctypes.byref(buf), ctypes.byref(c_password))
            return len(password)

        r = libcrypto.PEM_read_bio_PrivateKey(bp, None, CBFUNC(password_cb), None)

        if r:
            return r.contents
        raise PEMError('Wrong PEM data')

    @classmethod
    def public_from_pem_bytes(cls, data, password):
        bp = BIO.from_bytes(data)
        r = libcrypto.PEM_read_bio_PUBKEY(bp, None, 0, password)
        if r:
            return r.contents
        raise PEMError('Wrong PEM data')

    def new_ctx(self):
        r = libcrypto.EVP_PKEY_CTX_new(self, None)
        return r
    
libcrypto.PEM_read_bio_PrivateKey.argtypes = (
    POINTER(BIO), POINTER(POINTER(Pkey)), CBFUNC, c_void_p)

libcrypto.PEM_read_bio_PrivateKey.restype = POINTER(Pkey)

class OSSL_LIB_CTX(ctypes.Structure):
    pass


class OSSL_PROVIDER(ctypes.Structure):
    pass


class EVP_SIGNATURE(ctypes.Structure):
    pass


class ENGINE(ctypes.Structure):
    pass


class PkeyCtx(ctypes.Structure):

    def __new__(cls, *a, name=None, pkey=None, id=None, engine=None, **kw):
        if id:
            return libcrypto.EVP_PKEY_CTX_new_id(id, engine).contents
        if pkey:
            return libcrypto.EVP_PKEY_CTX_new(pkey, engine).contents
        if name:
            return libcrypto.EVP_PKEY_CTX_new_from_name(None, name.encode(), None).contents

    def __del__(self):
        libcrypto.EVP_PKEY_CTX_free(self)

    def paramgen_init(self):
        return libcrypto.EVP_PKEY_paramgen_init(self)

    def keygen_init(self):
        return libcrypto.EVP_PKEY_keygen_init(self)

    def keygen(self, key=None):
        self.paramgen_init()
        self.keygen_init()
        pkey = POINTER(Pkey)()

        #s = libcrypto.EVP_PKEY_paramgen(self, ctypes.byref(pkey))
        # print(s)
        #s = libcrypto.EVP_PKEY_keygen(self, ctypes.byref(pkey))
        s = libcrypto.EVP_PKEY_generate(self, ctypes.byref(pkey))

        if s == 1:
            return pkey.contents
        raise Error('EVP_PKEY_generate', s)

    def sign_init(self):
        return libcrypto.EVP_PKEY_sign_init(self)

    def sign(self, hash):
        self.sign_init()
        result_length = ctypes.c_size_t()
        if type(hash) == Digest:
            data = hash.digest()
        elif type(hash) == str:
            data = bytes.fromhex(hash)
        elif type(hash) == bytes:
            data = hash
        data_len = len(data)
        data = ctypes.cast(c_char_p(data), POINTER(c_ubyte))
        status = libcrypto.EVP_PKEY_sign(
            self, None, result_length, data, data_len)
        assert status == 1, "Failed to get signature length"
        result_buffer = ctypes.create_string_buffer(b'', result_length.value)
        status = libcrypto.EVP_PKEY_sign(
            self, result_buffer, result_length, data, data_len)
        assert status == 1, "Failed to sign a message"
        return result_buffer.raw[:result_length.value]

    def verify(self, sig, tbs):
        libcrypto.EVP_PKEY_verify_init(self)
        r = libcrypto.EVP_PKEY_verify(
            self, *bytes_to_ubyte_p(sig), *bytes_to_ubyte_p(tbs))
        if r < 0:
            raise Error('Verify error', r)
        return r == 1


def generate_key_pair(algo_name, params=[]):
    ctx = PkeyCtx(name=algo_name)
    for param in params:
        libcrypto.EVP_PKEY_CTX_ctrl_str(ctx, *param)
    key = ctx.keygen()
    return key


libcrypto.EVP_PKEY_CTX_ctrl_str.argtypes = (
    POINTER(PkeyCtx), c_char_p, c_char_p)

libcrypto.EVP_PKEY_verify_init.argtypes = (POINTER(PkeyCtx), )

libcrypto.EVP_PKEY_sign.argtypes = (
    POINTER(PkeyCtx), c_char_p, POINTER(c_size_t), POINTER(c_ubyte), c_size_t)

libcrypto.EVP_PKEY_verify.argtypes = (
    POINTER(PkeyCtx), POINTER(c_ubyte), c_size_t, POINTER(c_ubyte), c_size_t)


libcrypto.EVP_PKEY_sign_init.argtypes = (POINTER(PkeyCtx),)
libcrypto.EVP_PKEY_paramgen_init.argtypes = (POINTER(PkeyCtx),)
libcrypto.EVP_PKEY_keygen_init.argtypes = (POINTER(PkeyCtx),)

libcrypto.EVP_PKEY_keygen.argtypes = (POINTER(PkeyCtx), POINTER(POINTER(Pkey)))
libcrypto.EVP_PKEY_paramgen.argtypes = (
    POINTER(PkeyCtx), POINTER(POINTER(Pkey)))

libcrypto.EVP_PKEY_generate.argtypes = (
    POINTER(PkeyCtx), POINTER(POINTER(Pkey)))

libcrypto.EVP_PKEY_CTX_new_from_name.restype = POINTER(PkeyCtx)
libcrypto.EVP_PKEY_CTX_new_from_name.argtypes = (c_void_p, c_char_p, c_char_p)

libcrypto.EVP_PKEY_CTX_new_id.restype = POINTER(PkeyCtx)
libcrypto.EVP_PKEY_CTX_new_id.argtypes = (c_int, POINTER(ENGINE))

libcrypto.EVP_PKEY_CTX_new.restype = POINTER(PkeyCtx)
libcrypto.EVP_PKEY_CTX_new.argtypes = (POINTER(Pkey), POINTER(ENGINE))

libcrypto.EVP_PKEY_CTX_free.argtypes = (POINTER(PkeyCtx),)

libcrypto.X509_get_pubkey.argtypes = (POINTER(X509),)
libcrypto.X509_get_pubkey.restype = POINTER(Pkey)
libcrypto.PEM_read_bio_PUBKEY.restype = POINTER(Pkey)

