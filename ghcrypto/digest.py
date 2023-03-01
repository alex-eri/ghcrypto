from .lib import libcrypto, ctypes, MAX_MD_SIZE

from ctypes import c_char_p, c_void_p, c_long, c_int, c_uint, c_uint64, c_ulong, POINTER


class DigestError(Exception):
    pass


class DigestType(ctypes.Structure):
    _fields_ = [
        ('type', c_int),
        ('pkey_type', c_int),
        ('md_size', c_int),
        ('flags', c_ulong),
        ('init', c_void_p),
        ('update', c_void_p),
        ('final', c_void_p),
        ('copy', c_void_p),
        ('cleanup', c_void_p),
        ('sign', c_void_p),
        ('verify', c_void_p),
        ('required_pkey_type', c_int * 5),
        ('block size', c_int),
        ('ctx_size', c_int),
        ('md_ctrl', c_void_p),
    ]

    @classmethod
    def from_name(cls, digest_name):
        res = libcrypto.EVP_get_digestbyname(digest_name.encode('ascii'))
        if not res:
            raise DigestError("Unknown Digest: %(digest_name)s" % vars())
        return res.contents


class Digest(ctypes.Structure):
    _fields_ = [
        ('p_type', c_void_p),  # POINTER(DigestType)
        ('engine', c_void_p),  # todo, POINTER(ENGINE)
        ('flags', c_ulong),
        ('md_data', c_void_p),
        ('pctx', c_void_p),  # todo, POINTER(EVP_PKEY_CTX)
        ('update_func', c_void_p),
    ]
    finalized = False

    def __new__(cls, *a, **kw):
        return libcrypto.EVP_MD_CTX_new().contents

    def __del__(self):
        libcrypto.EVP_MD_CTX_free(self)

    def __init__(self, digest_type):
        self.digest_type = digest_type
        result = libcrypto.EVP_DigestInit_ex(self, digest_type, None)
        if result == 0:
            raise DigestError("Unable to initialize digest")

    def update(self, data):
        if self.finalized:
            raise DigestError("Digest is finalized; no updates allowed")

        result = libcrypto.EVP_DigestUpdate(self, data, len(data))
        if result != 1:
            raise DigestError("Unable to update digest")

    def digest(self, data=None):
        if data is not None:
            self.update(data)
        result_buffer = ctypes.create_string_buffer(MAX_MD_SIZE)
        result_length = ctypes.c_uint()
        res_code = libcrypto.EVP_DigestFinal_ex(
            self, result_buffer, result_length)
        if res_code != 1:
            raise DigestError("Unable to finalize digest")
        self.finalized = True
        result = result_buffer.raw[: result_length.value]
        # override self.digest to return the same result on subsequent
        #  calls
        self.digest = lambda: result
        return result


libcrypto.EVP_get_digestbyname.argtypes = (c_char_p,)
libcrypto.EVP_get_digestbyname.restype = POINTER(DigestType)
libcrypto.EVP_DigestInit.argtypes = (
    POINTER(Digest),
    POINTER(DigestType),
)
libcrypto.EVP_DigestInit_ex.argtypes = libcrypto.EVP_DigestInit.argtypes + \
    (c_void_p,)
libcrypto.EVP_DigestInit_ex.restype = c_int
libcrypto.EVP_DigestUpdate.argtypes = POINTER(Digest), c_char_p, c_int
libcrypto.EVP_DigestUpdate.restype = c_int
libcrypto.EVP_DigestFinal_ex.argtypes = (
    POINTER(Digest),
    c_char_p,
    POINTER(c_uint),
)
libcrypto.EVP_DigestFinal_ex.restype = c_int
libcrypto.EVP_MD_CTX_new.restype = POINTER(Digest)
libcrypto.EVP_MD_CTX_new.argtypes = None
libcrypto.EVP_MD_CTX_free.restype = None
libcrypto.EVP_MD_CTX_free.argtypes = (POINTER(Digest),)

