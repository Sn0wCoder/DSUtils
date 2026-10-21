import sys
import struct
import ctypes
from ctypes import wintypes, byref, c_void_p, POINTER, create_string_buffer

advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

PROV_RSA_FULL       = 1
CRYPT_VERIFYCONTEXT = 0xF0000000
AT_SIGNATURE        = 2
CRYPT_EXPORTABLE    = 0x00000001
PUBLICKEYBLOB       = 0x06
PRIVATEKEYBLOB      = 0x07

advapi32.CryptAcquireContextA.restype  = wintypes.BOOL
advapi32.CryptAcquireContextA.argtypes = [POINTER(c_void_p), wintypes.LPCSTR,
                                          wintypes.LPCSTR, wintypes.DWORD, wintypes.DWORD]
advapi32.CryptGenKey.restype    = wintypes.BOOL
advapi32.CryptGenKey.argtypes   = [c_void_p, wintypes.DWORD, wintypes.DWORD, POINTER(c_void_p)]
advapi32.CryptExportKey.restype  = wintypes.BOOL
advapi32.CryptExportKey.argtypes = [c_void_p, c_void_p, wintypes.DWORD, wintypes.DWORD,
                                    c_void_p, POINTER(wintypes.DWORD)]
advapi32.CryptDestroyKey.argtypes     = [c_void_p]
advapi32.CryptReleaseContext.argtypes = [c_void_p, wintypes.DWORD]


def export_blob(key, blob_type):

    n = wintypes.DWORD(0)
    advapi32.CryptExportKey(key, None, blob_type, 0, None, byref(n))
    buf = create_string_buffer(n.value)
    if not advapi32.CryptExportKey(key, None, blob_type, 0, buf, byref(n)):
        return None
    return buf.raw[:n.value]


def write_key_file(path, name, blob):
    with open(path, "wb") as f:
        f.write(name.encode("ascii") + b"\x00")
        f.write(struct.pack("<I", len(blob)))
        f.write(blob)


def main():
    if len(sys.argv) != 2:
        sys.stdout.write("Usage: dsCreateKey authority_name")
        sys.stdout.flush()
        return 1

    name = sys.argv[1]
    prov = c_void_p()
    key = c_void_p()

    if not advapi32.CryptAcquireContextA(byref(prov), None, None,
                                         PROV_RSA_FULL, CRYPT_VERIFYCONTEXT):
        print("CPAcquireContext failed")
        return 1
    try:

        if not advapi32.CryptGenKey(prov, AT_SIGNATURE,
                                    (1024 << 16) | CRYPT_EXPORTABLE, byref(key)):
            print("CPGenKey failed")
            return 1
        try:
            pub = export_blob(key, PUBLICKEYBLOB)
            priv = export_blob(key, PRIVATEKEYBLOB)
            if pub is None or priv is None:
                print("CryptExportKey failed")
                return 1
            write_key_file(name + ".bikey", name, pub)
            write_key_file(name + ".biprivatekey", name, priv)
            return 0
        finally:
            advapi32.CryptDestroyKey(key)
    finally:
        advapi32.CryptReleaseContext(prov, 0)


if __name__ == "__main__":
    sys.exit(main())
