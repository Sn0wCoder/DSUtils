import sys
import struct
import ctypes
from ctypes import wintypes, byref, c_void_p, POINTER, create_string_buffer

advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

PROV_RSA_FULL       = 1
CRYPT_VERIFYCONTEXT = 0xF0000000
AT_SIGNATURE        = 2
PUBLICKEYBLOB       = 0x06
CALG_SHA1           = 0x00008004

advapi32.CryptAcquireContextA.restype  = wintypes.BOOL
advapi32.CryptAcquireContextA.argtypes = [POINTER(c_void_p), wintypes.LPCSTR,
                                          wintypes.LPCSTR, wintypes.DWORD, wintypes.DWORD]
advapi32.CryptImportKey.restype  = wintypes.BOOL
advapi32.CryptImportKey.argtypes = [c_void_p, c_void_p, wintypes.DWORD, c_void_p,
                                    wintypes.DWORD, POINTER(c_void_p)]
advapi32.CryptExportKey.restype  = wintypes.BOOL
advapi32.CryptExportKey.argtypes = [c_void_p, c_void_p, wintypes.DWORD, wintypes.DWORD,
                                    c_void_p, POINTER(wintypes.DWORD)]
advapi32.CryptCreateHash.restype  = wintypes.BOOL
advapi32.CryptCreateHash.argtypes = [c_void_p, wintypes.DWORD, c_void_p,
                                     wintypes.DWORD, POINTER(c_void_p)]
advapi32.CryptHashData.restype  = wintypes.BOOL
advapi32.CryptHashData.argtypes = [c_void_p, c_void_p, wintypes.DWORD, wintypes.DWORD]
advapi32.CryptSignHashA.restype  = wintypes.BOOL
advapi32.CryptSignHashA.argtypes = [c_void_p, wintypes.DWORD, wintypes.LPCSTR,
                                    wintypes.DWORD, c_void_p, POINTER(wintypes.DWORD)]
advapi32.CryptDestroyHash.argtypes    = [c_void_p]
advapi32.CryptDestroyKey.argtypes     = [c_void_p]
advapi32.CryptReleaseContext.argtypes = [c_void_p, wintypes.DWORD]


def export_blob(key, blob_type):
    n = wintypes.DWORD(0)
    advapi32.CryptExportKey(key, None, blob_type, 0, None, byref(n))
    buf = create_string_buffer(n.value)
    advapi32.CryptExportKey(key, None, blob_type, 0, buf, byref(n))
    return buf.raw[:n.value]


def put_lv(parts, blob):
    parts.append(struct.pack("<I", len(blob)))
    parts.append(blob)


def main():
    if len(sys.argv) != 3:
        print("Usage: dsSignFile private_key_filename file_to_sign_filename")
        return 1

    key_path, data_path = sys.argv[1], sys.argv[2]

    try:
        kf = open(key_path, "rb").read()
    except OSError:
        print("Cannot open file '%s'" % key_path)
        return 1

    z = kf.find(b"\x00")
    if z < 0 or z + 5 > len(kf):
        print("Wrong private key file")
        return 1
    name = kf[:z].decode("ascii")
    (blob_len,) = struct.unpack_from("<I", kf, z + 1)
    blob_off = z + 5
    if blob_off + blob_len > len(kf):
        print("Wrong private key file")
        return 1
    blob = kf[blob_off:blob_off + blob_len]

    prov = c_void_p()
    key = c_void_p()
    hash_ = c_void_p()
    advapi32.CryptAcquireContextA(byref(prov), None, None,
                                  PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)
    try:
        blob_buf = create_string_buffer(blob, len(blob))
        if not advapi32.CryptImportKey(prov, blob_buf, len(blob), None, 0, byref(key)):
            print("CryptImportKey failed")
            return 1
        try:
            pub = export_blob(key, PUBLICKEYBLOB)

            data = open(data_path, "rb").read()

            if not advapi32.CryptCreateHash(prov, CALG_SHA1, None, 0, byref(hash_)):
                print("CryptCreateHash failed")
                return 1
            data_buf = create_string_buffer(data, len(data))
            if not advapi32.CryptHashData(hash_, data_buf, len(data), 0):
                print("CryptHashData failed")
                return 1

            n = wintypes.DWORD(0)
            advapi32.CryptSignHashA(hash_, AT_SIGNATURE, None, 0, None, byref(n))
            sig_buf = create_string_buffer(n.value)
            if not advapi32.CryptSignHashA(hash_, AT_SIGNATURE, None, 0, sig_buf, byref(n)):
                print("CryptSignHash failed.")
                return 1
            sig = sig_buf.raw[:n.value]

            parts = [name.encode("ascii") + b"\x00"]
            put_lv(parts, pub)                       # public key
            put_lv(parts, sig)                       # sig1
            parts.append(struct.pack("<I", 2))       # version
            put_lv(parts, sig)                       # sig2
            put_lv(parts, sig)                       # sig3

            out_path = "%s.%s.bisign" % (data_path, name)
            with open(out_path, "wb") as f:
                f.write(b"".join(parts))
            return 0
        finally:
            if hash_:
                advapi32.CryptDestroyHash(hash_)
            advapi32.CryptDestroyKey(key)
    finally:
        advapi32.CryptReleaseContext(prov, 0)


if __name__ == "__main__":
    sys.exit(main())
