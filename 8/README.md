# Set 8

**Link:** https://toadstyle.org/cryptopals/

57. Diffie-Hellman Revisited: Subgroup-Confinement Attacks
58. Pollard's Method for Catching Kangaroos
59. Elliptic Curve Diffie-Hellman and Invalid-Curve Attacks
60. Single-Coordinate Ladders and Insecure Twists
61. Duplicate-Signature Key Selection in ECDSA (and RSA)
62. Key-Recovery Attacks on ECDSA with Biased Nonces
63. Key-Recovery Attacks on GCM with Repeated Nonces
64. Key-Recovery Attacks on GCM with a Truncated MAC
65. Truncated-MAC GCM Revisited: Improving the Key-Recovery Attack
66. Exploiting Implementation Errors in Diffie-Hellman

## References

* 8.57: [Pohlig–Hellman](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm)
* 8.58: [Pollard's kangaroo](https://en.wikipedia.org/wiki/Pollard's_kangaroo_algorithm)
  * Pollard, [_Monte  Carlo  Methods  for  Index  Computation (mod  p)_](https://www.ams.org/journals/mcom/1978-32-143/S0025-5718-1978-0491431-9/S0025-5718-1978-0491431-9.pdf), 1978
* 8.59: [Weierstrass](https://en.wikipedia.org/wiki/Weierstrass_elliptic_function) [elliptic curve](https://en.wikipedia.org/wiki/Elliptic_curve)
* 8.60: [Montgomery curve](https://en.wikipedia.org/wiki/Montgomery_curve) (in particular equivalence and mapping)
  * [Explicit-Formulas Database](https://hyperelliptic.org/EFD/index.html)
* 8.61:
  * Blake-Wilson & Menezes, [_Unknown Key-Share Attacks on the Station-to-Station (STS) Protocol_](https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.30.1051&rep=rep1&type=pdf), 1999
* 8.62: [LLL](https://en.wikipedia.org/wiki/Lenstra%E2%80%93Lenstra%E2%80%93Lov%C3%A1sz_lattice_basis_reduction_algorithm)
  * Howgrave-Graham & Smart, [_Lattice Attacks on Digital Signature Schemes_](https://www.hpl.hp.com/techreports/1999/HPL-1999-90.pdf), pub. 2001 (rep.1999)
* 8.63: [GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
  * [GCM NIST specification](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
  * [Factorization of polynomials over finite fields](https://en.wikipedia.org/wiki/Factorization_of_polynomials_over_finite_fields), [Cantor–Zassenhaus](https://en.wikipedia.org/wiki/Cantor%E2%80%93Zassenhaus_algorithm)
  * Joux, [_Authentication Failures in NIST version of GCM_](https://csrc.nist.gov/csrc/media/projects/block-cipher-techniques/documents/bcm/comments/800-38-series-drafts/gcm/joux_comments.pdf), 2006
  * See also: Saarinen, [_Cycling Attacks on GCM (...)_](https://eprint.iacr.org/2011/202.pdf), 2011
* 8.64:
  * Ferguson, [_Authentication weaknesses in GCM_](https://csrc.nist.gov/CSRC/media/Projects/Block-Cipher-Techniques/documents/BCM/Comments/CWC-GCM/Ferguson2.pdf), 2005
