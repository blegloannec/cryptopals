#include <iostream>
#include <vector>
#include <random>
#include <cassert>
using namespace std;

typedef vector<uint8_t> bytes;

const int N = 1<<23;  // iterations
const string _msg = "BE_SURE_TO_DRINK_YOUR_OVALTINE";
const bytes _cookie(_msg.begin(), _msg.end());

random_device RNG;    // /dev/urandom

bytes randkey(unsigned int size=16) {
  bytes K(size);
  for (unsigned int k=0; k<size; ++k) K[k] = RNG();
  return K;
}


struct RC4 {
  uint8_t i, j, S[256];
  
  RC4(const bytes &K) {  // KSA
    int l = K.size();
    for (int i=0; i<256; ++i) S[i] = i;
    j = 0;
    for (int i=0; i<256; ++i) {
      j += S[i] + K[i%l];
      swap(S[i], S[j]);
    }
    i = j = 0;
  }
  
  uint8_t PRGA() {
    i += 1;
    j += S[i];
    swap(S[i], S[j]);
    uint8_t k = S[i]+S[j];
    return S[k];
  }
  
  // associated stream (en/de)cryption
  bytes encrypt(const bytes &msg) {
    bytes ciph;
    for (uint8_t b : msg) ciph.push_back(b^PRGA());
    return ciph;
  }
};


bytes oracle(const bytes &prefix) {
  bytes data = prefix;
  data.insert(data.end(), _cookie.begin(), _cookie.end());
  RC4 rc4(randkey());
  return rc4.encrypt(data);
}


#ifdef BIASES
int main() {
  vector<int> C16(256,0), C32(256,0);
  for (int i=0; i<N; ++i) {
    RC4 rc4(randkey());
    for (int k=0; k<32; ++k) {
      uint8_t x = rc4.PRGA();
      if (k==15) ++C16[x];
      if (k==31) ++C32[x];
    }
  }
  for (int i=0; i<256; ++i) cout << (double)C16[i]/(double)N << (i<255 ? ' ' : '\n');
  for (int i=0; i<256; ++i) cout << (double)C32[i]/(double)N << (i<255 ? ' ' : '\n');
  return 0;
}
#else
int main() {
  assert(_msg.size()<=32);
  int a = RNG()%16;  // targeted position in '#'*(32-_msg.size()) + _msg
  bytes prefix(32-_msg.size() + 15-a, '#');  // fill prefix with '#'
  for (auto c : prefix) cout << c;
  cout << _msg << endl;
  cout << "               |               |" << endl;
  vector<int> C16(256,0), C32(256,0);
  for (int i=0; i<N; ++i) {
    bytes ciph = oracle(prefix);
    ++C16[ciph[15]];
    ++C32[ciph[31]];
  }
  uint8_t b16=0, b32=0;
  for (int i=1; i<256; ++i) {
    if (C16[i]>C16[b16]) b16 = i;
    if (C32[i]>C32[b32]) b32 = i;
  }
  b16 ^= 240;  // bias at pos. 16 -> peak in 240
  b32 ^= 224;  //              32            224
  cout << "               " << b16 << "               " << b32 << endl;
  assert(b16 == (15<prefix.size() ? prefix[15] : _msg[15-prefix.size()]));
  assert(b32 == (31<prefix.size() ? prefix[31] : _msg[31-prefix.size()]));
  return 0;
}
#endif
