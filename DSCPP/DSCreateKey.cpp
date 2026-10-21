#include <windows.h>
#include <wincrypt.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#pragma comment(lib, "advapi32.lib")
static bool WriteKeyFile(const std::string& path, const char* name,
                         const BYTE* blob, DWORD blobLen)
{
    HANDLE h = CreateFileA(path.c_str(), GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return false;

    DWORD written = 0;
    bool ok = true;
    ok = ok && !!WriteFile(h, name, (DWORD)strlen(name) + 1, &written, NULL);
    ok = ok && !!WriteFile(h, &blobLen, sizeof(blobLen), &written, NULL);
    ok = ok && !!WriteFile(h, blob, blobLen, &written, NULL);
    CloseHandle(h);
    return ok;
}

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        printf("Usage: dsCreateKey authority_name");
        return 1;
    }

    const char* name = argv[1];

    HCRYPTPROV prov = 0;
    HCRYPTKEY  key  = 0;
    BYTE*      pub  = NULL;
    BYTE*      priv = NULL;
    DWORD      pubLen = 0, privLen = 0;
    int        rc = 1;

    if (!CryptAcquireContextA(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        printf("CPAcquireContext failed\n");
    }
    else if (!CryptGenKey(prov, AT_SIGNATURE,
                          (1024 << 16) | CRYPT_EXPORTABLE, &key))
    {
        printf("CPGenKey failed\n");
    }
    else
    {
        CryptExportKey(key, 0, PUBLICKEYBLOB, 0, NULL, &pubLen);
        pub = (BYTE*)malloc(pubLen);
        CryptExportKey(key, 0, PRIVATEKEYBLOB, 0, NULL, &privLen);
        priv = (BYTE*)malloc(privLen);

        if (!CryptExportKey(key, 0, PUBLICKEYBLOB, 0, pub, &pubLen) ||
            !CryptExportKey(key, 0, PRIVATEKEYBLOB, 0, priv, &privLen))
        {
            printf("CryptExportKey failed\n");
        }
        else
        {
            WriteKeyFile(std::string(name) + ".bikey",        name, pub,  pubLen);
            WriteKeyFile(std::string(name) + ".biprivatekey", name, priv, privLen);
            rc = 0;
        }
    }

    free(pub);
    free(priv);
    if (key)  CryptDestroyKey(key);
    if (prov) CryptReleaseContext(prov, 0);
    return rc;
}
