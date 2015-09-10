#include <openssl/sha.h>
#include <openssl/evp.h>
#include <string>
#include <sstream>

using namespace std;

unsigned char* Sha256(const string str)
{
    unsigned char* hash = new unsigned char[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);

    return hash;
}

unsigned char* Sha256(unsigned char* data, size_t length)
{
    unsigned char* hash = new unsigned char[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, length);
    SHA256_Final(hash, &sha256);

    return hash;
}

string ByteArrayToString(unsigned char* data, size_t length)
{
    stringstream ss;

    for (size_t i = 0; i < length; i++)
        ss << hex << uppercase << (int) data[i];

    return ss.str();
}

void PBKDF2_HMAC_SHA_256(const char* pass, const unsigned char* salt, int iterations, int outputBytes, unsigned char* digest)
{
    //unsigned char digest[outputBytes];
    PKCS5_PBKDF2_HMAC(pass, sizeof(pass), salt, sizeof(salt), iterations, EVP_sha256(), outputBytes, digest);

    //memcpy(result, digest, outputBytes);
}
