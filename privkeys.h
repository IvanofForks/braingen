#ifndef PRIVKEYS_H
#define PRIVKEYS_H

unsigned char* GetXPrivKey(unsigned char* privateKey, bool testnet=false);
unsigned char* GetXPrivChecksum(unsigned char* xPrivateKey);
unsigned char* XPrivKeyToWif(unsigned char* xPrivateKey);
string WifToBase58(unsigned char* wif);

#endif
