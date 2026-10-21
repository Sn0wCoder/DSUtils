#include <windows.h>
#include <wincrypt.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")

static bool ReadWholeFile(const char* path, std::vector<BYTE>& out)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return false;

    DWORD size = GetFileSize(h, NULL);
    out.resize(size);
    DWORD read = 0;
    bool ok = (size == 0) || !!ReadFile(h, out.data(), size, &read, NULL);
    CloseHandle(h);
    return ok && read == size;
}

static void PutLV(std::vector<BYTE>& v, const BYTE* data, DWORD len)
{
    v.insert(v.end(), (BYTE*)&len, (BYTE*)&len + 4);
    v.insert(v.end(), data, data + len);
}

int main(int argc, char** argv)
{
    if (argc != 3)
    {
        printf("Usage: dsSignFile private_key_filename file_to_sign_filename\n");
        return 1;
    }

    const char* keyPath  = argv[1];
    const char* dataPath = argv[2];

    std::vector<BYTE> kf;
    if (!ReadWholeFile(keyPath, kf))
    {
        printf("Cannot open file '%s'\n", keyPath);
        return 1;
    }

    size_t z = 0;
    while (z < kf.size() && kf[z] != 0) ++z;
    if (z + 5 > kf.size())
    {
        printf("Wrong private key file\n");
        return 1;
    }
    std::string name((char*)kf.data(), z);

    DWORD blobLen = 0;
    memcpy(&blobLen, &kf[z + 1], 4);
    size_t blobOff = z + 5;
    if (blobOff + blobLen > kf.size())
    {
        printf("Wrong private key file\n");
        return 1;
    }

    HCRYPTPROV prov = 0;
    HCRYPTKEY  key  = 0;
    HCRYPTHASH hash = 0;
    int rc = 1;

    CryptAcquireContextA(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);

    if (!CryptImportKey(prov, &kf[blobOff], blobLen, 0, 0, &key))
    {
        printf("CryptImportKey failed\n");
    }
    else
    {
        DWORD pubLen = 0;
        CryptExportKey(key, 0, PUBLICKEYBLOB, 0, NULL, &pubLen);
        std::vector<BYTE> pub(pubLen);
        CryptExportKey(key, 0, PUBLICKEYBLOB, 0, pub.data(), &pubLen);

        std::vector<BYTE> data;
        ReadWholeFile(dataPath, data);

        bool ok = true;
        if (!CryptCreateHash(prov, CALG_SHA1, 0, 0, &hash))
        {
            printf("CryptCreateHash failed\n"); ok = false;
        }
        else if (!CryptHashData(hash, data.empty() ? (BYTE*)"" : data.data(),
                                (DWORD)data.size(), 0))
        {
            printf("CryptHashData failed\n"); ok = false;
        }

        DWORD sigLen = 0;
        std::vector<BYTE> sig;
        if (ok)
        {
            CryptSignHashA(hash, AT_SIGNATURE, NULL, 0, NULL, &sigLen);
            sig.resize(sigLen);
            if (!CryptSignHashA(hash, AT_SIGNATURE, NULL, 0, sig.data(), &sigLen))
            {
                printf("CryptSignHash failed.\n"); ok = false;
            }
        }

        if (ok)
        {
            const DWORD version = 2;
            std::vector<BYTE> out;
            out.insert(out.end(), name.begin(), name.end());
            out.push_back(0);
            PutLV(out, pub.data(), pubLen);                 // public key
            PutLV(out, sig.data(), sigLen);                 // sig1
            out.insert(out.end(), (BYTE*)&version, (BYTE*)&version + 4);
            PutLV(out, sig.data(), sigLen);                 // sig2
            PutLV(out, sig.data(), sigLen);                 // sig3

            std::string outPath = std::string(dataPath) + "." + name + ".bisign";
            HANDLE h = CreateFileA(outPath.c_str(), GENERIC_WRITE, 0, NULL,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (h != INVALID_HANDLE_VALUE)
            {
                DWORD written = 0;
                WriteFile(h, out.data(), (DWORD)out.size(), &written, NULL);
                CloseHandle(h);
                rc = 0;
            }
        }
    }

    if (hash) CryptDestroyHash(hash);
    if (key)  CryptDestroyKey(key);
    if (prov) CryptReleaseContext(prov, 0);
    return rc;
}
