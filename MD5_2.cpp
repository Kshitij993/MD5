#include<bits/stdc++.h>

typedef unsigned char uint1; //  8bit
typedef unsigned int uint4;  // 32bit
  
using namespace std;

class MD5
{ 
public:
  typedef unsigned int size_type; // must be 32bit
 
  MD5();
  MD5(const string& text);
  void update(const unsigned char *buf, size_type length);
  void update(const char *buf, size_type length);
  MD5& finalize();
  string hexdigest() const;
  friend ostream& operator<<(ostream&, MD5 md5);
  
private:
  void init();
  typedef unsigned char uint1; //  8bit
  typedef unsigned int uint4;  // 32bit
  enum {blocksize = 64}; 	  	// VC6 won't eat a const static int here
 
  void transform(const uint1 block[blocksize]);
  static void decode(uint4 output[], const uint1 input[], size_type len);
  static void encode(uint1 output[], const uint4 input[], size_type len);
 
  bool finalized;
  uint1 buffer[blocksize]; // bytes that didn't fit in last 64 byte chunk
  uint4 count[2];   			// 64bit counter for number of bits (lo, hi)
  uint4 state[4];   			// digest so far
  uint1 digest[16]; 			// the result
 
  // low level logic operations
  static inline uint4 F(uint4 x, uint4 y, uint4 z);
  static inline uint4 G(uint4 x, uint4 y, uint4 z);
  static inline uint4 H(uint4 x, uint4 y, uint4 z);
  static inline uint4 I(uint4 x, uint4 y, uint4 z);
  static inline uint4 rotate_left(uint4 x, int n);
  static inline void FF(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac);
  static inline void GG(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac);
  static inline void HH(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac);
  static inline void II(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac);
};

const uint4 shift_R1[]={7,12,17,22};
const uint4 shift_R2[]={5,9,14,20};
const uint4 shift_R3[]={4,11,16,23};
const uint4 shift_R4[]={6,10,15,21};

const uint4 t[]={0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,0x698098d8,0x8b44f7af,
0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x2441453,
0xd8a1e681,0xe7d3fbc8,0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,0xfffa3942,0x8771f681,
0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,0x289b7ec6,0xeaa127fa,0xd4ef3085,0x4881d05,0xd9d4d039,0xe6db99e5,
0x1fa27cf8,0xc4ac5665,0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,0x6fa87e4f,0xfe2ce6e0,
0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};

// F, G, H and I are basic MD5 functions.
inline MD5::uint4 MD5::F(uint4 x, uint4 y, uint4 z) 
{
  return x&y | ~x&z;
}
 
inline MD5::uint4 MD5::G(uint4 x, uint4 y, uint4 z) 
{
  return x&z | y&~z;
}
 
inline MD5::uint4 MD5::H(uint4 x, uint4 y, uint4 z) 
{
  return x^y^z;
}
 
inline MD5::uint4 MD5::I(uint4 x, uint4 y, uint4 z) 
{
  return y ^ (x | ~z);
}
 
// rotate_left rotates x left n bits.
inline MD5::uint4 MD5::rotate_left(uint4 x, int n) 
{
  return (x << n) | (x >> (32-n));
}
 
// FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
// Rotation is separate from addition to prevent recomputation.
inline void MD5::FF(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) 
{
  a = rotate_left(a+ F(b,c,d) + x + ac, s) + b;
}
 
inline void MD5::GG(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) 
{
  a = rotate_left(a + G(b,c,d) + x + ac, s) + b;
}
 
inline void MD5::HH(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) 
{
  a = rotate_left(a + H(b,c,d) + x + ac, s) + b;
}
 
inline void MD5::II(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) 
{
  a = rotate_left(a + I(b,c,d) + x + ac, s) + b;
}

MD5::MD5()
{
  init();
}
// nifty shortcut ctor, compute MD5 for string and finalize it right away
MD5::MD5(const std::string &text)
{
  init();
  update(text.c_str(), text.length());
  finalize();
}
 
void MD5::init()
{
  finalized=false;
 
  count[0] = 0;
  count[1] = 0;
 
  // load magic initialization constants.
  state[0] = 0x67452301;
  state[1] = 0xefcdab89;
  state[2] = 0x98badcfe;
  state[3] = 0x10325476;
}
 
// decodes input (unsigned char) into output (uint4). Assumes len is a multiple of 4.
void MD5::decode(uint4 output[], const uint1 input[], size_type len)
{
  for (unsigned int i = 0, j = 0; j < len; i++, j += 4)
    output[i] = ((uint4)input[j]) | (((uint4)input[j+1]) << 8) |
      (((uint4)input[j+2]) << 16) | (((uint4)input[j+3]) << 24);
}
 
// encodes input (uint4) into output (unsigned char). Assumes len is
// a multiple of 4.
void MD5::encode(uint1 output[], const uint4 input[], size_type len)
{
  for (size_type i = 0, j = 0; j < len; i++, j += 4) {
    output[j] = input[i] & 0xff;
    output[j+1] = (input[i] >> 8) & 0xff;
    output[j+2] = (input[i] >> 16) & 0xff;
    output[j+3] = (input[i] >> 24) & 0xff;
  }
}

// apply MD5 algo on a block
void MD5::transform(const uint1 block[blocksize])
{
  uint4 x[16];
  decode (x, block, blocksize);
 
  int i,j=0;
  int a=0,b=1,c=2,d=3,temp;
  for( i=0;i<16;i++)
  {
  		FF(state[a],state[b],state[c],state[d],x[i],shift_R1[i%4],t[j]);
  		temp=a;
  		a=d;
  		d=c;
  		c=b;
  		b=temp;
  		j++;
  }
  a=0,b=1,c=2,d=3;
  for(i=0;i<16;i++)
  {
  		GG(state[a],state[b],state[c],state[d],x[i],shift_R2[i%4],t[j]);
  		temp=a;
  		a=d;
  		d=c;
  		c=b;
  		b=temp;
  		j++;
  }
  a=0,b=1,c=2,d=3;
  for(i=0;i<16;i++)
  {
  		HH(state[a],state[b],state[c],state[d],x[i],shift_R3[i%4],t[j]);
  		temp=a;
  		a=d;
  		d=c;
  		c=b;
  		b=temp;
  		j++;
  }
  a=0,b=1,c=2,d=3;
  for(i=0;i<16;i++)
  {
  		II(state[a],state[b],state[c],state[d],x[i],shift_R4[i%4],t[j]);
  		temp=a;
  		a=d;
  		d=c;
  		c=b;
  		b=temp;
  		j++;
  }
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
 
  // Zeroize sensitive information.
  memset(x, 0, sizeof x);
}
 
// MD5 block update operation. Continues an MD5 message-digest
// operation, processing another message block
void MD5::update(const unsigned char input[], size_type length)
{
  // compute number of bytes mod 64
  size_type index = count[0] / 8 % blocksize;
 
  // Update number of bits
  if ((count[0] += (length << 3)) < (length << 3))
    count[1]++;
  count[1] += (length >> 29);
 
  // number of bytes we need to fill in buffer
  size_type firstpart = 64 - index;
 
  size_type i;
 
  // transform as many times as possible.
  if (length >= firstpart)
  {
    // fill buffer first, transform
    memcpy(&buffer[index], input, firstpart);
    transform(buffer);
 
    // transform chunks of blocksize (64 bytes)
    for (i = firstpart; i + blocksize <= length; i += blocksize)
      transform(&input[i]);
 
    index = 0;
  }
  else
    i = 0;
 
  // buffer remaining input
  memcpy(&buffer[index], &input[i], length-i);
}
 
// for convenience provide a verson with signed char
void MD5::update(const char input[], size_type length)
{
  update((const unsigned char*)input, length);
}
 
// MD5 finalization. Ends an MD5 message-digest operation, writing the
// the message digest and zeroizing the context.
MD5& MD5::finalize()
{
  static unsigned char padding[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
  };
 
  if (!finalized) {
    // Save number of bits
    unsigned char bits[8];
    encode(bits, count, 8);
 
    // pad out to 56 mod 64.
    size_type index = count[0] / 8 % 64;
    size_type padLen = (index < 56) ? (56 - index) : (120 - index);
    update(padding, padLen);
 
    // Append length (before padding)
    update(bits, 8);
 
    // Store state in digest
    encode(digest, state, 16);
 
    // Zeroize sensitive information.
    memset(buffer, 0, sizeof buffer);
    memset(count, 0, sizeof count);
 
    finalized=true;
  }
 
  return *this;
}
 
// return hex representation of digest as string
string MD5::hexdigest() const
{
  if (!finalized)
    return "";
 
  char buf[33];
  for (int i=0; i<16; i++)
    sprintf(buf+i*2, "%02x", digest[i]);
  buf[32]=0;
 
  return string(buf);
}
 
ostream& operator<<(ostream& out, MD5 md5)
{
  return out << md5.hexdigest();
}
 
string md5(const std::string str)
{
    MD5 md5 = MD5(str);
 
    return md5.hexdigest();
}

int main(int argc, char *argv[])
{
    cout << "md5 of 'grape': " << md5("grape") << endl;
    return 0;
}

