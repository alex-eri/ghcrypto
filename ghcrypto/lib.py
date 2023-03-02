import ctypes
import sys
from ctypes.util import find_library
from ctypes import CDLL, c_char_p, c_void_p, c_long, c_uint64, POINTER

if sys.platform.startswith('win'):
    __libname__ = find_library('libeay32')
else:
    __libname__ = find_library('crypto')

libcrypto = ctypes.CDLL(__libname__)

libcrypto.OPENSSL_config.argtypes = (c_char_p, )

if hasattr(libcrypto, 'OPENSSL_init_crypto'):
    libcrypto.OPENSSL_init_crypto.argtypes = (c_uint64, c_void_p)
    libcrypto.OPENSSL_init_crypto(2+4+8+0x40+0x400+0x800+0x2000, None)
    strings_loaded = True
else:
    libcrypto.OPENSSL_add_all_algorithms_conf()
    strings_loaded = False

MAX_MD_SIZE = 64
