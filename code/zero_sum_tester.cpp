// Compile with: g++ -std=c++0x -g -O2 -funroll-loops -march=native -mtune=native zero_sum_tester.cpp -o zero_sum_tester -lcrypto -lm

#include <cmath> // log2(.)
#include <cstring> // memcpy
#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <set>
#include <openssl/rand.h> // For RAND_bytes(.)

#define WORDSIZE 64

#define VERBOSE

#define deg(x) (uint32)floor(log2((double)x))
#define SBOX_DEGREE 3
#define SBOX_DEGREE_NUM_SQUARINGS (uint32)(log2(SBOX_DEGREE))
// #define REDUCE_DEGREE_TWICE // Used for degrees 2^n - 1 (e.g., goes from x^9 to x^7)

typedef unsigned short uint16;
typedef unsigned int uint32;
typedef unsigned long uint64;
typedef __uint128_t uint128;
typedef unsigned char uchar;
typedef uint64 word;
typedef uint128 doubleword;

// Globals
void (*bf_add)(word* c, word* a, word* b);
void (*bf_mul)(word* c, word* a, word* b);
//void (*bf_sbox)(word* c, word* a);
void (*cipher)(word* in, word* out, word* round_keys, word* round_constants, uint32 num_rounds, uint32 n, uint32 t, uchar* data);
doubleword IRRED_POLY = 0;
uint32 FIELD_SIZE = 0;

void print_hex(void* source, uint32 num_bytes) {
  // TEMP
  uchar* pointer = (uchar*)source;
  for(uint32 i = 0; i < num_bytes; i++) {
    std::cout << std::setfill('0') << std::setw(2) << std::hex << (uint32)(pointer[num_bytes - i - 1]);
  }
  std::cout << std::dec << std::endl;
}

std::string to_string_hex(void* source, uint32 num_bytes) {
  uchar* pointer = (uchar*)source;
  std::ostringstream string_stream;
  for(uint32 i = 0; i < num_bytes; i++) {
    string_stream << std::setfill('0') << std::setw(2) << std::hex << (uint32)(pointer[num_bytes - i - 1]);
  }
  std::string ret_string = string_stream.str();
  return ret_string;
}

std::string to_string_binary(void* source, uint32 num_bytes) {
  uchar* pointer = (uchar*)source;
  std::ostringstream string_stream;
  for(uint32 i = 0; i < num_bytes; i++) {
    for(uint32 j = 0; j < 8; j++) {
      string_stream << (((uint32)(pointer[num_bytes - i - 1]) >> (7 - j)) & 0x1);
    }
  }
  std::string ret_string = string_stream.str();
  return ret_string;
}

void bf_add_generic(word* c, word* a, word* b) {
  c[0] = a[0] ^ b[0];
}

void bf_inverse(word* c_inv, word* c) {
  doubleword u = *c;
  doubleword v = IRRED_POLY;
  doubleword g1 = 1;
  doubleword g2 = 0;
  int j = 0;
  doubleword tmp = 0;
  if(*c == 0) {
    *c_inv = 0;
    return;
  }
  while(deg(u) != 0) {
  //while(u != 1) {
    j = deg(u) - deg(v);
    if(j < 0) {
      tmp = u;
      u = v;
      v = tmp;
      tmp = g1;
      g1 = g2;
      g2 = tmp;
      j = -j;
    }
    u = u ^ (v << j);
    g1 = g1 ^ (g2 << j);
  }
  *c_inv = (word)(g1);
}

void bf_3_add(word* c, word* a, word* b) {
  c[0] = a[0] ^ b[0];
}

inline void bf_3_mul(word* c, word* a, word* b) {
  doubleword r = 0;
  asm("pclmulqdq %2, %1, %0;"
    : "=x"(r)
    : "x"(a[0]), "i"(0), "0"(b[0])
    );
  
  // Irred poly: x^3 + x + 1
  word c0 = r & 0x7; // LS 3 bits
  word c1 = (r & 0x18) >> 3; // MS 2 bits

  // Add c1 to bits 1 and 0 of c0 (c1 doesn't neet to be done first, because it's not affected)
  *c = c0 ^ (c1 << 1) ^ c1;

  //std::cout << "a * b = " << *a << " * " << *b << " = " << *c << std::endl;
}

inline void bf_3_cube(word* c, word* a) {
  word t1 = 0;
  word t2 = 0;
  bf_3_mul(&t1, a, a);
  bf_3_mul(&t2, &t1, a);
  *c = t2;
}

void bf_7_add(word* c, word* a, word* b) {
  c[0] = a[0] ^ b[0];
}

inline void bf_7_mul(word* c, word* a, word* b) {
  doubleword r = 0;
  asm("pclmulqdq %2, %1, %0;"
    : "=x"(r)
    : "x"(a[0]), "i"(0), "0"(b[0])
    );
  
  // Irred poly: x^7 + x + 1
  word c0 = r & 0x7F; // LS 7 bits
  word c1 = r >> 7; // MS 6 bits

  c1 = c1 ^ (c1 >> 6);
  c0 = c0 ^ (c1 << 1) ^ c1;

  // Build result
  *c = c0 & 0x7F;
}

inline void bf_7_cube(word* c, word* a) {
  word t1 = 0;
  word t2 = 0;
  bf_7_mul(&t1, a, a);
  bf_7_mul(&t2, &t1, a);
  *c = t2;
}

void bf_9_add(word* c, word* a, word* b) {
  c[0] = a[0] ^ b[0];
}

inline void bf_9_mul(word* c, word* a, word* b) {
  doubleword r = 0;
  asm("pclmulqdq %2, %1, %0;"
    : "=x"(r)
    : "x"(a[0]), "i"(0), "0"(b[0])
    );
  
  // Irred poly: x^9 + x + 1
  word c0 = r & 0x1FF; // LS 9 bits
  word c1 = r >> 9; // MS 8 bits

  c1 = c1 ^ (c1 >> 8);
  c0 = c0 ^ (c1 << 1) ^ c1;

  // Build result
  *c = c0 & 0x1FF;
}

inline void bf_9_cube(word* c, word* a) {
  word t1 = 0;
  word t2 = 0;
  bf_9_mul(&t1, a, a);
  bf_9_mul(&t2, &t1, a);
  *c = t2;
}

void bf_11_add(word* c, word* a, word* b) {
  c[0] = a[0] ^ b[0];
}

inline void bf_11_mul(word* c, word* a, word* b) {
  doubleword r = 0;
  asm("pclmulqdq %2, %1, %0;"
    : "=x"(r)
    : "x"(a[0]), "i"(0), "0"(b[0])
    );

  // Irred poly: x^11 + x^2 + 1
  word c0 = r & 0x7FF; // LS 11 bits
  word c1 = r >> 11; // MS 10 bits

  c1 = c1 ^ (c1 >> 9);
  c0 = c0 ^ (c1 << 2) ^ c1;

  // Build result
  *c = c0 & 0x7FF;
}

inline void bf_11_cube(word* c, word* a) {
  word t1 = 0;
  word t2 = 0;
  bf_11_mul(&t1, a, a);
  bf_11_mul(&t2, &t1, a);
  *c = t2;
}

void bf_13_add(word* c, word* a, word* b) {
  c[0] = a[0] ^ b[0];
}

inline void bf_13_mul(word* c, word* a, word* b) {
  doubleword r = 0;
  asm("pclmulqdq %2, %1, %0;"
    : "=x"(r)
    : "x"(a[0]), "i"(0), "0"(b[0])
    );

  // Irred poly: x^13 + x^4 + x^3 + x + 1
  word c0 = r & 0x1FFF; // LS 13 bits
  word c1 = r >> 13; // MS 12 bits

  c1 = c1 ^ (c1 >> 9) ^ (c1 >> 10) ^ (c1 >> 12);
  c0 = c0 ^ (c1 << 4) ^ (c1 << 3) ^ (c1 << 1) ^ c1;

  // Build result
  *c = c0 & 0x1FFF;
}

inline void bf_13_cube(word* c, word* a) {
  word t1 = 0;
  word t2 = 0;
  bf_13_mul(&t1, a, a);
  bf_13_mul(&t2, &t1, a);
  *c = t2;
}

void bf_15_add(word* c, word* a, word* b) {
  c[0] = a[0] ^ b[0];
}

inline void bf_15_mul(word* c, word* a, word* b) {
  doubleword r = 0;
  asm("pclmulqdq %2, %1, %0;"
    : "=x"(r)
    : "x"(a[0]), "i"(0), "0"(b[0])
    );

  // Irred poly: x^15 + x + 1
  word c0 = r & 0x7FFF; // LS 15 bits
  word c1 = r >> 15; // MS 14 bits

  c1 = c1 ^ (c1 >> 14);
  c0 = c0 ^ (c1 << 1) ^ c1;

  // Build result
  *c = c0 & 0x7FFF;
}

inline void bf_15_cube(word* c, word* a) {
  word t1 = 0;
  word t2 = 0;
  bf_15_mul(&t1, a, a);
  bf_15_mul(&t2, &t1, a);
  *c = t2;
}

void bf_17_add(word* c, word* a, word* b) {
  c[0] = a[0] ^ b[0];
}

inline void bf_17_mul(word* c, word* a, word* b) {
  doubleword r = 0;
  asm("pclmulqdq %2, %1, %0;"
    : "=x"(r)
    : "x"(a[0]), "i"(0), "0"(b[0])
    );

  // Irred poly: x^17 + x^3 + 1
  word c0 = r & 0x1FFFF; // LS 17 bits
  word c1 = r >> 17; // MS 16 bits
  
  c1 = c1 ^ (c1 >> 14);
  c0 = c0 ^ (c1 << 3) ^ c1;
  
  // Build result
  *c = c0 & 0x1FFFF;
}

inline void bf_17_cube(word* c, word* a) {
  word t1 = 0;
  word t2 = 0;
  bf_17_mul(&t1, a, a);
  bf_17_mul(&t2, &t1, a);
  *c = t2;
}

void bf_19_add(word* c, word* a, word* b) {
  c[0] = a[0] ^ b[0];
}

inline void bf_19_mul(word* c, word* a, word* b) {
  doubleword r = 0;
  asm("pclmulqdq %2, %1, %0;"
    : "=x"(r)
    : "x"(a[0]), "i"(0), "0"(b[0])
    );

  // Irred poly: x^19 + x^5 + x^2 + x + 1
  word c0 = r & 0x7FFFF; // LS 19 bits
  word c1 = r >> 19; // MS 18 bits
  
  c1 = c1 ^ (c1 >> 14) ^ (c1 >> 17) ^ (c1 >> 18);
  c0 = c0 ^ (c1 << 5) ^ (c1 << 2) ^ (c1 << 1) ^ c1;
  
  // Build result
  *c = c0 & 0x7FFFF;
}

inline void bf_19_cube(word* c, word* a) {
  word t1 = 0;
  word t2 = 0;
  bf_19_mul(&t1, a, a);
  bf_19_mul(&t2, &t1, a);
  *c = t2;
}

void bf_21_add(word* c, word* a, word* b) {
  c[0] = a[0] ^ b[0];
}

inline void bf_21_mul(word* c, word* a, word* b) {
  doubleword r = 0;
  asm("pclmulqdq %2, %1, %0;"
    : "=x"(r)
    : "x"(a[0]), "i"(0), "0"(b[0])
    );

  // Irred poly: x^21 + x^2 + 1
  word c0 = r & 0x1FFFFF; // LS 21 bits
  word c1 = r >> 21; // MS 20 bits
  
  c1 = c1 ^ (c1 >> 19);
  c0 = c0 ^ (c1 << 2) ^ c1;
  
  // Build result
  *c = c0 & 0x1FFFFF;
}

inline void bf_21_cube(word* c, word* a) {
  word t1 = 0;
  word t2 = 0;
  bf_21_mul(&t1, a, a);
  bf_21_mul(&t2, &t1, a);
  *c = t2;
}

void bf_23_add(word* c, word* a, word* b) {
  c[0] = a[0] ^ b[0];
}

inline void bf_23_mul(word* c, word* a, word* b) {
  doubleword r = 0;
  asm("pclmulqdq %2, %1, %0;"
    : "=x"(r)
    : "x"(a[0]), "i"(0), "0"(b[0])
    );

  // Irred poly: x^23 + x^5 + 1
  word c0 = r & 0x7FFFFF; // LS 23 bits
  word c1 = r >> 23; // MS 22 bits
  
  c1 = c1 ^ (c1 >> 18);
  c0 = c0 ^ (c1 << 5) ^ c1;
  
  // Build result
  *c = c0 & 0x7FFFFF;
}

inline void bf_23_cube(word* c, word* a) {
  word t1 = 0;
  word t2 = 0;
  bf_23_mul(&t1, a, a);
  bf_23_mul(&t2, &t1, a);
  *c = t2;
}

void bf_25_add(word* c, word* a, word* b) {
  c[0] = a[0] ^ b[0];
}

inline void bf_25_mul(word* c, word* a, word* b) {
  doubleword r = 0;
  asm("pclmulqdq %2, %1, %0;"
    : "=x"(r)
    : "x"(a[0]), "i"(0), "0"(b[0])
    );

  // Irred poly: x^25 + x^3 + 1
  word c0 = r & 0x1FFFFFF; // LS 25 bits
  word c1 = r >> 25; // MS 24 bits
  
  c1 = c1 ^ (c1 >> 22);
  c0 = c0 ^ (c1 << 3) ^ c1;
  
  // Build result
  *c = c0 & 0x1FFFFFF;
}

inline void bf_25_cube(word* c, word* a) {
  word t1 = 0;
  word t2 = 0;
  bf_25_mul(&t1, a, a);
  bf_25_mul(&t2, &t1, a);
  *c = t2;
}

void bf_27_add(word* c, word* a, word* b) {
  c[0] = a[0] ^ b[0];
}

inline void bf_27_mul(word* c, word* a, word* b) {
  doubleword r = 0;
  asm("pclmulqdq %2, %1, %0;"
    : "=x"(r)
    : "x"(a[0]), "i"(0), "0"(b[0])
    );

  // Irred poly: x^27 + x^5 + x^2 + x + 1
  word c0 = r & 0x7FFFFFF; // LS 27 bits
  word c1 = r >> 27; // MS 26 bits
  
  c1 = c1 ^ (c1 >> 22) ^ (c1 >> 25) ^ (c1 >> 26);
  c0 = c0 ^ (c1 << 5) ^ (c1 << 2) ^ (c1 << 1) ^ c1;
  
  // Build result
  *c = c0 & 0x7FFFFFF;
}

inline void bf_27_cube(word* c, word* a) {
  word t1 = 0;
  word t2 = 0;
  bf_27_mul(&t1, a, a);
  bf_27_mul(&t2, &t1, a);
  *c = t2;
}

void bf_29_add(word* c, word* a, word* b) {
  c[0] = a[0] ^ b[0];
}

inline void bf_29_mul(word* c, word* a, word* b) {
  doubleword r = 0;
  asm("pclmulqdq %2, %1, %0;"
    : "=x"(r)
    : "x"(a[0]), "i"(0), "0"(b[0])
    );

  // Irred poly: x^29 + x^2 + 1
  word c0 = r & 0x1FFFFFFF; // LS 29 bits
  word c1 = r >> 29; // MS 28 bits
  
  c1 = c1 ^ (c1 >> 27);
  c0 = c0 ^ (c1 << 2) ^ c1;
  
  // Build result
  *c = c0 & 0x1FFFFFFF;
}

inline void bf_29_cube(word* c, word* a) {
  word t1 = 0;
  word t2 = 0;
  bf_29_mul(&t1, a, a);
  bf_29_mul(&t2, &t1, a);
  *c = t2;
}

void bf_31_add(word* c, word* a, word* b) {
  c[0] = a[0] ^ b[0];
}

inline void bf_31_mul(word* c, word* a, word* b) {
  doubleword r = 0;
  asm("pclmulqdq %2, %1, %0;"
    : "=x"(r)
    : "x"(a[0]), "i"(0), "0"(b[0])
    );

  // Irred poly: x^31 + x^3 + 1
  word c0 = r & 0x7FFFFFFF; // LS 31 bits
  word c1 = r >> 31; // MS 30 bits
  
  c1 = c1 ^ (c1 >> 28);
  c0 = c0 ^ (c1 << 3) ^ c1;
  
  // Build result
  *c = c0 & 0x7FFFFFFF;
}

inline void bf_31_cube(word* c, word* a) {
  word t1 = 0;
  word t2 = 0;
  bf_31_mul(&t1, a, a);
  bf_31_mul(&t2, &t1, a);
  *c = t2;
}

void bf_32_add(word* c, word* a, word* b) {
  c[0] = a[0] ^ b[0];
}

inline void bf_32_mul(word* c, word* a, word* b) {
  doubleword r = 0;
  asm("pclmulqdq %2, %1, %0;"
    : "=x"(r)
    : "x"(a[0]), "i"(0), "0"(b[0])
    );
  
  // Irred poly: x^32 + x^7 + x^3 + x^2 + 1
  word c0 = r & 0xFFFFFFFF; // LS 32 bits
  word c1 = r >> 32; // MS 31 bits

  word T = c1;
  c1 = c1 ^ (T >> 25) ^ (T >> 29) ^ (T >> 30); // 25 = 32 - 7, 29 = 32 - 3, 30 = 32 - 2, x^0 does not affect c1
  T = c1;
  *c = c0 ^ ((T << 7) & 0xFFFFFFFF) ^ ((T << 3) & 0xFFFFFFFF) ^ ((T << 2) & 0xFFFFFFFF) ^ T; // = c0, for x^6, x^3, x^1, x^0
}

inline void bf_32_cube(word* c, word* a) {
  word t1 = 0;
  word t2 = 0;
  bf_32_mul(&t1, a, a);
  bf_32_mul(&t2, &t1, a);
  *c = t2;
}

void bf_33_add(word* c, word* a, word* b) {
  c[0] = a[0] ^ b[0];
}

inline void bf_33_mul(word* c, word* a, word* b) {
  doubleword r = 0;
  asm("pclmulqdq %2, %1, %0;"
    : "=x"(r)
    : "x"(a[0]), "i"(0), "0"(b[0])
    );

  // Irred poly: x^33 + x^6 + x^3 + x + 1
  word c0 = r & 0x1FFFFFFFF; // LS 33 bits
  word c1 = r >> 33; // MS 32 bits

  word T = c1;
  c1 = c1 ^ (T >> 27) ^ (T >> 30); // 27 = 33 - 6, 30 = 33 - 3, 32 = 33 - 1 (omitted, all zeros), x^0 does not affect c1
  T = c1;
  *c = c0 ^ ((T << 6) & 0x1FFFFFFFF) ^ ((T << 3) & 0x1FFFFFFFF) ^ ((T << 1) & 0x1FFFFFFFF) ^ T; // = c0, for x^6, x^3, x^1, x^0
}

inline void bf_33_cube(word* c, word* a) {
  word t1 = 0;
  word t2 = 0;
  bf_33_mul(&t1, a, a);
  bf_33_mul(&t2, &t1, a);
  *c = t2;
}

void bf_35_add(word* c, word* a, word* b) {
  c[0] = a[0] ^ b[0];
}

inline void bf_35_mul(word* c, word* a, word* b) {
  doubleword r = 0;
  asm("pclmulqdq %2, %1, %0;"
    : "=x"(r)
    : "x"(a[0]), "i"(0), "0"(b[0])
    );

  // Irred poly: x^35 + x^2 + 1
  word c0 = r & 0x7FFFFFFFF; // LS 35 bits
  word c1 = r >> 35; // MS 34 bits
  
  c1 = c1 ^ (c1 >> 33);
  c0 = c0 ^ (c1 << 2) ^ c1;
  
  // Build result
  *c = c0 & 0x7FFFFFFFF;
}

inline void bf_35_cube(word* c, word* a) {
  word t1 = 0;
  word t2 = 0;
  bf_35_mul(&t1, a, a);
  bf_35_mul(&t2, &t1, a);
  *c = t2;
}

inline void bf_sbox(word* c, word* a) {
  word t1 = 0;
  // word tmp = 0;
  // bf_mul(&tmp, a, a);
  // bf_mul(&tmp, &tmp, a);
  // bf_mul(&tmp, &tmp, a);
  // bf_mul(&tmp, &tmp, a);
  // bf_mul(&tmp, &tmp, a);
  // bf_mul(&tmp, &tmp, a);
  // std::cout << "T1: " << to_string_hex(&tmp, 4) << std::endl;
  //*c = tmp;
  //return;
  // Squarings
  //std::cout << "number of squarings: " << SBOX_DEGREE_NUM_SQUARINGS << std::endl;
  // std::cout << "a: " << to_string_hex(a, 8) << std::endl;
  bf_mul(&t1, a, a);
  for(uint32 i = 0; i < SBOX_DEGREE_NUM_SQUARINGS - 1; i++) {
    bf_mul(&t1, &t1, &t1);
  }
  // Final multiplication with original a
  bf_mul(&t1, &t1, a);
  //std::cout << "c: " << *c << std::endl;

  #ifndef REDUCE_DEGREE_TWICE
  *c = t1;
  #endif
  #ifdef REDUCE_DEGREE_TWICE
  // Goes from degree 2^n + 1 to degree 2^n - 1
  // Calculate inverse of original a
  word temp = 0;
  bf_inverse(&temp, a);
  // Square inverse
  bf_mul(&temp, &temp, &temp);
  // Multiply previous result with square of the inverse
  bf_mul(&temp, &t1, &temp);
  *c = temp;
  #endif
  // std::cout << "c: " << to_string_hex(c, 8) << std::endl;
  // exit(1);
}

inline void bf_sbox_inverse_3(word* c, word* a) {
  // Calculate inverse of x^3, which is x^((2^(n+1) - 1) / 3) for field size n
  // The exponent is 0b1010..0101, where the number of 1 bits is ceil(n/2) (e.g., 0b10101 = 21 for n = 5)
  word t1 = 0;
  uint64 mul_positions = 0x5555555555555555 & (0xFFFFFFFFFFFFFFFF >> WORDSIZE - FIELD_SIZE);
  
  word temp = *a;
  *c = temp;
  for(uint32 i = 1; i < FIELD_SIZE; i++) {
    bf_mul(&temp, &temp, &temp);
    if(((mul_positions >> i) & 0x1) == 0x1) {
      bf_mul(c, c, &temp);
    }
  }
}

void mimc(word* in, word* out, word* round_keys, word* round_constants, uint32 num_rounds, uint32 n, uint32 t, uchar* data) {

  // Values to work with
  word value_branch = 0;
  word key = round_keys[0];

  // Assign values
  value_branch = in[0];

  // Set first round constant to zero
  round_constants[0] = 0;

  // Cipher implementation
  for(uint32 i = 0; i < num_rounds; i++) {
    value_branch ^= key;
    value_branch ^= round_constants[i];
    bf_sbox(&value_branch, &value_branch);
    //bf_sbox_inverse_3(&value_branch, &value_branch);
    //std::cout << "Round " << (i + 1) << " finished." << std::endl;
  }
  value_branch ^= key;

  // Write to out
  out[0] = value_branch;
}

int main(int argc, char** argv) {

  std::cout << "Starting..." << std::endl;

  if(argc != 4) {
    std::cout << "Usage: <program> <n> <num_rounds> <num_bits_active>" << std::endl;
    return 1;
  }

  // Fetch from command line parameters
  uint64 n = std::stoi(argv[1]);
  uint64 t = 1;
  uint64 N = n;
  uint64 num_rounds = std::stoi(argv[2]);
  uint64 num_bits_active = std::stoi(argv[3]);

  // Set globals
  FIELD_SIZE = n;

  // Settings
  if(num_bits_active == 0) {
    num_bits_active = N - 1; // N - 1
  }
  uint64 bit_inactive = num_bits_active;
  uint64 begin_at_branch = 0;
  cipher = &mimc;
  bool rand_input = true;
  bool rand_round_keys = true;
  bool rand_constants = true;
  bool binary_output = true;

  word in[t];
  word in_copy[t];
  word out[t];

  if(n == 7) {
    bf_add = &bf_add_generic;
    bf_mul = &bf_7_mul;
    //bf_sbox = &bf_7_cube;
    IRRED_POLY = 0x83;
  }
  else if(n == 9) {
    bf_add = &bf_add_generic;
    bf_mul = &bf_9_mul;
    //bf_sbox = &bf_9_cube;
    IRRED_POLY = 0x203;
  }
  else if(n == 11) {
    bf_add = &bf_add_generic;
    bf_mul = &bf_11_mul;
    //bf_sbox = &bf_11_cube;
    IRRED_POLY = 0x805;
  }
  else if(n == 13) {
    bf_add = &bf_add_generic;
    bf_mul = &bf_13_mul;
    //bf_sbox = &bf_13_cube;
    IRRED_POLY = 0x201b;
  }
  else if(n == 15) {
    bf_add = &bf_add_generic;
    bf_mul = &bf_15_mul;
    //bf_sbox = &bf_15_cube;
    IRRED_POLY = 0x8003;
  }
  else if(n == 17) {
    bf_add = &bf_add_generic;
    bf_mul = &bf_17_mul;
    //bf_sbox = &bf_17_cube;
    IRRED_POLY = 0x20009;
  }
  else if(n == 19) {
    bf_add = &bf_add_generic;
    bf_mul = &bf_19_mul;
    //bf_sbox = &bf_19_cube;
    IRRED_POLY = 0x80027;
  }
  else if(n == 21) {
    bf_add = &bf_add_generic;
    bf_mul = &bf_21_mul;
    //bf_sbox = &bf_21_cube;
    IRRED_POLY = 0x200005;
  }
  else if(n == 23) {
    bf_add = &bf_add_generic;
    bf_mul = &bf_23_mul;
    //bf_sbox = &bf_23_cube;
    IRRED_POLY = 0x800021;
  }
  else if(n == 25) {
    bf_add = &bf_add_generic;
    bf_mul = &bf_25_mul;
    //bf_sbox = &bf_25_cube;
    IRRED_POLY = 0x2000009;
  }
  else if(n == 27) {
    bf_add = &bf_add_generic;
    bf_mul = &bf_27_mul;
    //bf_sbox = &bf_27_cube;
    IRRED_POLY = 0x8000027;
  }
  else if(n == 29) {
    bf_add = &bf_add_generic;
    bf_mul = &bf_29_mul;
    //bf_sbox = &bf_29_cube;
    IRRED_POLY = 0x20000005;
  }
  else if(n == 31) {
    bf_add = &bf_add_generic;
    bf_mul = &bf_31_mul;
    //bf_sbox = &bf_31_cube;
    IRRED_POLY = 0x80000009;
  }
  else if(n == 33) {
    bf_add = &bf_add_generic;
    bf_mul = &bf_33_mul;
    //bf_sbox = &bf_33_cube;
    IRRED_POLY = 0x20000004b;
  }
  else if(n == 35) {
    bf_add = &bf_add_generic;
    bf_mul = &bf_35_mul;
    //bf_sbox = &bf_35_cube;
    IRRED_POLY = 0x800000005;
  }
  else {
    std::cout << "[ERROR] Undefined field size " << n << ". Please use [7, 9, ..., 35]." << std::endl;
    exit(1);
  }

  std::cout << "[INFO] Irred poly: " << to_string_hex(&IRRED_POLY, 16) << std::endl;

  //word matrix[8][8];
  //init_mds_matrix((void*)matrix, n, 8, 1);

  uint64 branch_size = ceil(((float)n / WORDSIZE) * 8);
  uint64 word_unused_bits = (WORDSIZE - (n % WORDSIZE)) % WORDSIZE;
  uint64 used_mask = 0xFFFFFFFFFFFFFFFF >> word_unused_bits;

  memset(in, 0x0, t * sizeof(word));

  // Randomize input
  for(uint32 i = 0; i < t; i++) {
    if(rand_input == true)
      RAND_bytes((uchar*)&(in[i]), branch_size);
    else
      memset(&(in[i]), 0x0, branch_size);
      //memset(&(in[i]), 0x0, branch_size);
      //memset(&(in[i]), 0x03, branch_size);
    in[i] = in[i] & used_mask;
    std::cout << "Input (Branch " << i << "): " << std::hex << in[i] << std::dec << std::endl;
  }

  memcpy(in_copy, in, t * sizeof(word));
  memset(out, 0x0, t * sizeof(word));

  // Zero Sum test
  uint32 num_round_constants = 0;
  uint32 num_round_keys = 0;
  word* data = NULL; // Storage for matrices, and so on...

  // Prepare for MiMC
  num_round_constants = num_rounds;
  num_round_keys = 1;

  word round_constants[num_round_constants];
  word round_keys[num_round_keys];

  // Randomize key and constants
  /*
  RAND_bytes((uchar*)&(key), branch_size);
  key = key & used_mask;
  std::cout << "Key: " << to_string_hex(&key, branch_size) << std::endl;
  for(uint32 i = 0; i < num_rounds; i++) {
    RAND_bytes((uchar*)&(round_constants[i]), branch_size);
    round_constants[i] = round_constants[i] & used_mask;
    std::cout << "RC " << i << ": " << to_string_hex(&(round_constants[i]), branch_size) << std::endl;
  }
  */
  for(uint32 i = 0; i < num_round_constants; i++) {
    if(rand_constants == true)
      RAND_bytes((uchar*)&(round_constants[i]), branch_size);
    else
      memset(&(round_constants[i]), 0x0, branch_size);
    round_constants[i] = round_constants[i] & used_mask;
    //round_constants[i] = 0;
    std::cout << "RC " << i << ": " << to_string_hex(&(round_constants[i]), branch_size) << std::endl;
  }

  for(uint32 i = 0; i < num_round_keys; i++) {
    if(rand_round_keys == true)
      RAND_bytes((uchar*)&(round_keys[i]), branch_size);
    else
      memset(&(round_keys[i]), 0x0, branch_size);
    round_keys[i] = round_keys[i] & used_mask;
    //round_keys[i] = 0;
    std::cout << "RK " << i << ": " << to_string_hex(&(round_keys[i]), branch_size) << std::endl;
  }

  uint64 num_texts = (uint64)0x1 << num_bits_active;
  word in_sum[t];
  word out_sum[t];
  memset(in_sum, 0x0, t * sizeof(word));
  memset(out_sum, 0x0, t * sizeof(word));

  // Print settings
  uint32 sbox_degree = SBOX_DEGREE;
  #ifdef REDUCE_DEGREE_TWICE
  sbox_degree -= 2;
  #endif
  std::cout << "Field size n: " << n << std::endl;
  std::cout << "Number of rounds: " << num_rounds << std::endl;
  std::cout << "Number of active bits: " << num_bits_active << std::endl;
  std::cout << "Inactive bit index in active bits: " << bit_inactive << std::endl;
  std::cout << "Number of input texts: " << num_texts << std::endl;
  std::cout << "S-box: x^" << sbox_degree << std::endl;

  //std::set<word> branch_values;
  word test_vector_plaintext[t];
  word test_vector_ciphertext[t];
  memset(test_vector_plaintext, 0x0, t * sizeof(word));
  memset(test_vector_ciphertext, 0x0, t * sizeof(word));

  uint32 num_affected_branches = ceil((float)num_bits_active / n);

  uint64 i_split = 0;
  uint64 shift_amount = std::min(1, (int)(num_bits_active - bit_inactive)); // either 0 or 1
  for(uint64 i = 0; i < num_texts; i++) {
    // Set difference
    for(uint32 j = 0; j < num_affected_branches; j++) {
      //std::cout << "--- --- --- --- ---" << std::endl;
      //std::cout << "i: " << to_string_binary(&i, sizeof(word) / 2) << std::endl;
      i_split = ((i & (((uint64)0x1 << bit_inactive) - 1)) | ((i << shift_amount) & ~(((uint64)0x1 << (bit_inactive + 1)) - 1))) & (used_mask << (j * n));
      //std::cout << "i_split: " << to_string_binary(&i_split, sizeof(word) / 2) << std::endl;
      in_copy[j + begin_at_branch] = in[j + begin_at_branch] ^ ((i_split >> (j * n)) & used_mask);
      //std::cout << "mask: " << std::hex << used_mask << std::dec << std::endl;
      //std::cout << "(i, j) = (" << i << ", " << j << "): " << to_string_binary(&(in_copy[j + begin_at_branch]), 2) << std::endl;
    }

    // Update input sum
    for(uint32 j = 0; j < t; j++) {
      in_sum[j] ^= in_copy[j];
    }

    if(i == 0) {
      for(uint32 j = 0; j < t; j++) {
        memcpy(&(test_vector_plaintext[j]), &(in_copy[j]), sizeof(word));
      }
    }

    cipher(in_copy, out, round_keys, round_constants, num_rounds, n, t, (uchar*)data);

    // Update output sum
    for(uint32 j = 0; j < t; j++) {
      out_sum[j] ^= out[j];
    }

    if(i == 0) {
      for(uint32 j = 0; j < t; j++) {
        memcpy(&(test_vector_ciphertext[j]), &(out[j]), sizeof(word));
      }
    }

    //branch_values.insert((out[2] << (2*n)) | (out[1] << n) | out[0]);
  }

  //std::cout << "Unique output values: " << branch_values.size() << std::endl;

  // Print input sums
  for(uint32 i = 0; i < t; i++) {
    std::cout << "[I] Branch " << i << ": " << to_string_hex(&(in_sum[i]), sizeof(word) / 2) << std::endl;
  }

  std::cout << "----------" << std::endl;

  // Print test vectors for x-th pair
  for(uint32 i = 0; i < t; i++) {
    std::cout << "[Test Vector - PT] Branch " << i << ": " << to_string_hex(&(test_vector_plaintext[i]), branch_size) << std::endl;
  }

  for(uint32 i = 0; i < t; i++) {
    std::cout << "[Test Vector - CT] Branch " << i << ": " << to_string_hex(&(test_vector_ciphertext[i]), branch_size) << std::endl;
  }

  std::cout << "----------" << std::endl;

  // Print output sums
  std::cout << "Out (hex):" << std::endl;
  for(uint32 i = 0; i < t; i++) {
    std::cout << "[O] Branch " << i << ": " << to_string_hex(&(out_sum[i]), sizeof(word) / 2) << std::endl;
  }
  if(binary_output == true) {
    std::cout << "Out (bin):" << std::endl;
    for(uint32 i = 0; i < t; i++) {
      std::cout << "[O] Branch " << i << ": " << to_string_binary(&(out_sum[i]), sizeof(word) / 2) << std::endl;
    }
  }
  //for(uint32 i = 0; i < t; i++) {
  //  std::cout << std::setfill('0') << std::setw(8) << std::hex << in_sum[i] << std::dec << std::endl;
  //}

  if(data != NULL) {
    delete[] data;
  }

  return 0;
}
