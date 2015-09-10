// Copyright (c) 2015 The braingen developers
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include <iostream>
#include <openssl/evp.h>
#include <cstring>
#include <unistd.h>
#include <termios.h>
#include <stdio.h>
#include "crypto.h"
#include "privkeys.h"

using namespace std;

static void ShowUsage()
{
    cerr << "Usage: braingen [-t][-s][-a algorithm][-i iterations][-v]\n"
            << "Options:\n"
            << "  -t\tTestnet\n"
            << "  -s\tGenerate a private key based on a single SHA-256 round (NOT RECOMMENDED)\n"
            << "  -a\tUse a specific hash algorithm for the KDF, one of: RIPEMD160, SHA256, SHA512. Default is SHA256\n"
            << "  -i\tSpecify the number of PBKDF2 iterations. Default is 200 000\n"
            << "  -v\tDisplay passphrases"
            << endl;
}

void SetStdinEcho(bool enable)
{
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if( !enable )
        tty.c_lflag &= ~ECHO;
    else
        tty.c_lflag |= ECHO;

    (void) tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

int main(int argc, char* argv[])
{
    //if there are no arguments, we will generate a PK based on 200 000 PBKDF2 iterations using SHA-256
    bool singleSha = false, displayPassphases = false, testnet = false;
    int iterations = 200000;
    string algo = "SHA256";

    for (int i=1; i<argc; i++)
    {
        string currentArg(argv[i]), nextArg;

        if (i == argc-1)
            nextArg = "";
        else
            nextArg = string(argv[i+1]);


        if (currentArg == "-s")
            singleSha = true;
        else if (currentArg == "-t")
            testnet = true;
        else if (currentArg == "-v")
            displayPassphases = true;
        else if (i<argc-1 && currentArg == "-a" && (nextArg == "RIPEMD160" || nextArg == "SHA256" || nextArg == "SHA512"))
        {
            algo = nextArg;
            i++;
        }
        else if (i<argc-1 && currentArg == "-i" && sscanf(nextArg.c_str(), "%i", &iterations))
        {
            if (iterations < 1)
            {
                ShowUsage();
                return 1;
            }
            else if (iterations < 50000)
                cout << "WARNING: Low number of iterations selected, consider using 50 000 or more" << endl;

            i++;
        }
        else
        {
            ShowUsage();
            return 1;
        }

    }

    if (singleSha)
    {
        string passphrase;

        cout << "Generating a private key based on a single SHA-256 hash..." << endl;

        if (!displayPassphases)
            SetStdinEcho(false);

        cout << "Please enter the passphrase:" << endl;
        cin >> passphrase;

        if (!displayPassphases)
            SetStdinEcho(true);

        cout << "Private key:" << endl
                << WifToBase58(XPrivKeyToWif(GetXPrivKey(Sha256(passphrase), testnet))) << endl;
    }
    else
    {
        string passphrase, salt, tmp;

        cout << "Generating a private key based on " << iterations << " of PBKDF2 with the " << algo << " algorithm..." << endl;

        if (!displayPassphases)
            SetStdinEcho(false);

        cout << "Please enter the passphrase:" << endl;
        cin >> passphrase;

        cout << "Please enter the salt:" << endl;
        cin >> salt;

        if (!displayPassphases)
        {
            cout << "Please confirm the passphrase:" << endl;
            cin >> tmp;

            if (tmp != passphrase)
            {
                cout << "ERROR: Passphrase mismatch." << endl;
                SetStdinEcho(true);
                return 1;
            }

            cout << "Please confirm the salt:" << endl;
            cin >> tmp;

            SetStdinEcho(true);

            if (tmp != salt)
            {
                cout << "ERROR: Salt mismatch." << endl;
                return 1;
            }
        }

        unsigned char csalt[salt.length()];
        strcpy((char*)csalt, salt.c_str());

        unsigned char digest[32];

        if (algo == "RIPEMD160")
            PKCS5_PBKDF2_HMAC(passphrase.c_str(), passphrase.length(), csalt, salt.length(), iterations, EVP_ripemd160(), 32, digest);
        else if (algo == "SHA256")
            PKCS5_PBKDF2_HMAC(passphrase.c_str(), passphrase.length(), csalt, salt.length(), iterations, EVP_sha256(), 32, digest);
        else if (algo == "SHA512")
            PKCS5_PBKDF2_HMAC(passphrase.c_str(), passphrase.length(), csalt, salt.length(), iterations, EVP_sha512(), 32, digest);

        cout << "Private key:" << endl
                << WifToBase58(XPrivKeyToWif(GetXPrivKey(digest, testnet))) << endl;
    }

    return 0;
}
