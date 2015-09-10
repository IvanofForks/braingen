# braingen
A simple CLI application to generate Bitcoin private keys from text input. However, unlike common brainwallet tools, braingen offers the possibility to use PBKDF2 to derive a private key from a passphrase and a salt. Optionally, a custom algorithm (SHA-256, SHA-512 or RIPEMD160) or number of iterations (default 200000) may also be specified.
The use of a robust key derivation function with plenty of iterations and a salt makes generating and monitoring massive databases of private keys derived from common terms, phrases and variations thereof impractical.

***THIS IS BETA SOFTWARE, PLEASE TREAT IT AS SUCH. I TAKE NO RESPONSIBILITY FROM ANY ISSUES ARISING FROM ITS USE.***

# Usage
Usage: braingen [-t][-s][-a algorithm][-i iterations][-v]
Options:
  -t	Testnet
  -s	Generate a private key based on a single SHA-256 round (NOT RECOMMENDED)
  -a	Use a specific hash algorithm for the KDF, one of: RIPEMD160, SHA256, SHA512. Default is SHA256
  -i	Specify the number of PBKDF2 iterations. Default is 200 000
  -v	Display passphrases
