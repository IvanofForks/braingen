#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>

using namespace std;

unsigned char* Sha256(const string str);
unsigned char* Sha256(unsigned char* data, size_t length);
string ByteArrayToString(unsigned char* data, size_t length);
void PBKDF2_HMAC_SHA_256(const char* pass, const unsigned char* salt, int iterations, int outputBytes, unsigned char* digest);

#endif
