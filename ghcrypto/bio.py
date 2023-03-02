import ctypes

from .lib import libcrypto

from ctypes import c_void_p,c_long,POINTER,c_int,c_char_p


class BIO(ctypes.Structure):
    @classmethod
    def from_bytes(cls, data):
        return libcrypto.BIO_new_mem_buf(data, len(data)).contents

    def __del__(self):
        libcrypto.BIO_free(self)


libcrypto.BIO_s_mem.restype = POINTER(BIO)
libcrypto.BIO_new.restype = POINTER(BIO)
libcrypto.BIO_new.argtypes = (c_void_p, )
libcrypto.BIO_ctrl.restype = c_long
libcrypto.BIO_ctrl.argtypes = (POINTER(BIO), c_int, c_long, POINTER(c_char_p))
libcrypto.BIO_read.argtypes = (POINTER(BIO), c_char_p, c_int)
libcrypto.BIO_write.argtypes = (POINTER(BIO), c_char_p, c_int)
libcrypto.BIO_free.argtypes = (POINTER(BIO), )
libcrypto.BIO_new_mem_buf.restype = POINTER(BIO)
libcrypto.BIO_new_mem_buf.argtypes = (c_char_p, c_int)

