#include <string>
#include <cstring>
#include "crypto.h"
#include "base58.h"

unsigned char* GetXPrivKey(unsigned char* privateKey, bool testnet=false)
{
    unsigned char* xPrivKey = new unsigned char[33];

    if (!testnet)
        xPrivKey[0] = 0x80;
    else
        xPrivKey[0] = 0xEF;

    memcpy(xPrivKey + 0x1, privateKey, 32);

    return xPrivKey;
}

unsigned char* GetXPrivChecksum(unsigned char* xPrivateKey)
{
    unsigned char* checksum = new unsigned char[4];
    unsigned char* sha1 = Sha256(xPrivateKey, 33);
    unsigned char* sha2 = Sha256(sha1, 32);

    memcpy(checksum, sha2, 4);

    return checksum;
}

unsigned char* XPrivKeyToWif(unsigned char* xPrivateKey)
{
    unsigned char* xPrivWif = new unsigned char[37];
    memcpy(xPrivWif, xPrivateKey, 33);

    unsigned char* checksum = GetXPrivChecksum(xPrivateKey);
    memcpy(xPrivWif+33, checksum, 4);

    delete[] checksum;

    return xPrivWif;
}

string WifToBase58(unsigned char* wif)
{
    return EncodeBase58(wif, wif+37);
}
