# Cryptopals Crypto Challenges

**Link:** https://cryptopals.com/

## Resources

* [PyCryptodome](https://www.pycryptodome.org/en/latest/src/api.html)
* [IACR Publications DB](https://www.iacr.org/publications/access.php)

## Bibliography

* 2.9: [PKSC](https://en.wikipedia.org/wiki/PKCS) #7 - RFC [5652](https://tools.ietf.org/html/rfc5652)
* 3.17: [CBC padding oracle](https://en.wikipedia.org/wiki/Padding_oracle_attack)
  * Vaudenay, [_Security Flaws Induced by CBC Padding_](https://www.iacr.org/cryptodb/archive/2002/EUROCRYPT/2850/2850.pdf), 2002
* 3.21-24: [Mersenne Twister (pseudocode)](https://en.wikipedia.org/wiki/Mersenne_Twister)
  * Makoto Matsumoto's [MT page](http://www.math.sci.hiroshima-u.ac.jp/m-mat/MT/emt.html)
* 4.28-29: [SHA-1 (pseudocode)](https://en.wikipedia.org/wiki/SHA-1)
* 4.30: [MD4](https://en.wikipedia.org/wiki/MD4)
  * RFC [1186](https://datatracker.ietf.org/doc/html/rfc1186), [1320](https://datatracker.ietf.org/doc/html/rfc1320), [6150](https://datatracker.ietf.org/doc/html/rfc6150)
* 4.31-32: [HMAC](https://en.wikipedia.org/wiki/HMAC)
  * RFC [2104](https://datatracker.ietf.org/doc/html/rfc2104)
* 5.33-35: [Diffie–Hellman](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)
  * RFC [3526](https://datatracker.ietf.org/doc/html/rfc3526/)
* 5.36-38: [SRP](https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol)
  * Tom Wu's [SRP page](http://srp.stanford.edu/)
  * RFC [2945](https://datatracker.ietf.org/doc/html/rfc2945)
* 5.39-40: [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
  * [PKSC](https://en.wikipedia.org/wiki/PKCS) #1 - RFC [8017](https://www.rfc-editor.org/rfc/rfc3447.html)
* 6.42: [Bleichenbacher's attack (2006)](https://en.wikipedia.org/wiki/Daniel_Bleichenbacher)
  * Hal Finney's [writeup](https://mailarchive.ietf.org/arch/msg/openpgp/5rnE9ZRN1AokBVj3VqblGlP63QE/)
* 6.43-45: [DSA](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm)
  * 6.45: Vaudenay, [_The Security of DSA and ECDSA_](https://www.iacr.org/archive/pkc2003/25670309/25670309.pdf), 2003
* 6.46-48: [Bleichenbacher's attack (1998)](https://en.wikipedia.org/wiki/Adaptive_chosen-ciphertext_attack#Practical_attacks)
  * Bleichenbacher, [_Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1_](https://link.springer.com/content/pdf/10.1007%2FBFb0055716.pdf), 1998
  * See also: Fujisaki–Okamoto–Pointcheval–Stern, [_RSA-OAEP Is Secure under the RSA Assumption_](https://www.di.ens.fr/~pointche/Documents/Papers/2004_joc.pdf), 2004
* 7.49-50: [CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)
  * 7.50: Matthew Green's [blog post](https://blog.cryptographyengineering.com/2013/02/15/why-i-hate-cbc-mac/)
* 7.51:
  * [CRIME attack](https://docs.google.com/presentation/d/11eBmGiHbYcHR9gL5nDyZChu_-lCa2GizeuOfaLU2HOU)
* 7.52: [Merkle–Damgård](https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction)
  * Joux, [_Multicollisions in iterated hash functions_](https://www.iacr.org/archive/crypto2004/31520306/multicollisions.pdf), 2004
* 7.53:
  * Kelsey–Schneier, [_Second Preimages on n-bit Hash Functions for Much Less than 2ⁿ Work_](https://eprint.iacr.org/2004/304.pdf), 2004
* 7.54:
  * Kelsey–Kohno, [_Herding Hash Functions and the Nostradamus Attack_](https://homes.cs.washington.edu/~yoshi/papers/EC06/herding.pdf), 2006
* 7.55:
  * Wang _et al._, [_Cryptanalysis of the Hash Functions MD4 and RIPEMD_](https://www.iacr.org/archive/eurocrypt2005/34940001/34940001.pdf), 2005
* 7.56: [On the Security of RC4 in TLS and WPA](http://www.isg.rhul.ac.uk/tls/)

## Using Python 3

#### Related modules

* `os`: contains [`urandom()`](https://docs.python.org/3/library/os.html#os.urandom)
* [`secrets`](https://docs.python.org/3/library/secrets.html): secure (strongly non predictable and reproducible) alternative to the [`random`](https://docs.python.org/3/library/random.html) module (Mersenne Twister-based pseudo-random number generator, reproducible)
* [`hashlib`](https://docs.python.org/3/library/hashlib.html): secure hash functions
* [`hmac`](https://docs.python.org/3/library/hmac.html): keyed-hashing for authentication
* [`base64`](https://docs.python.org/3/library/base64.html)
* [`binascii`](https://docs.python.org/3/library/binascii.html)

#### Conversions

```
bytes   -> int             int.from_bytes(b, 'big')
int     -> bytes           i.to_bytes(length, 'big')
                           i.to_bytes((i.bit_length()+7)//8, 'big')
bytes   -> hex str         b.hex()
hex str -> bytes           bytes.fromhex(h)
```

```
int -> hex repr (0x..)     hex(i)
int -> bin repr (0b..)     bin(i)
```
