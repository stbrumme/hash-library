// //////////////////////////////////////////////////////////
// sha256.cpp
// Copyright (c) 2014,2015,2021 Stephan Brumme. All rights reserved.
// see http://create.stephan-brumme.com/disclaimer.html
//

#include "sha256.h"

//#define SHA2_224_SEED_VECTOR


/// same as reset()
SHA256::SHA256()
{
  reset();
}


/// restart
void SHA256::reset()
{
  m_numBytes   = 0;
  m_bufferSize = 0;

  // according to RFC 1321
  // "These words were obtained by taking the first thirty-two bits of the
  //  fractional parts of the square roots of the first eight prime numbers"
  m_hash[0] = 0x6a09e667;
  m_hash[1] = 0xbb67ae85;
  m_hash[2] = 0x3c6ef372;
  m_hash[3] = 0xa54ff53a;
  m_hash[4] = 0x510e527f;
  m_hash[5] = 0x9b05688c;
  m_hash[6] = 0x1f83d9ab;
  m_hash[7] = 0x5be0cd19;

#ifdef SHA2_224_SEED_VECTOR
  // if you want SHA2-224 instead then use these seeds
  // and throw away the last 32 bits of getHash
  m_hash[0] = 0xc1059ed8;
  m_hash[1] = 0x367cd507;
  m_hash[2] = 0x3070dd17;
  m_hash[3] = 0xf70e5939;
  m_hash[4] = 0xffc00b31;
  m_hash[5] = 0x68581511;
  m_hash[6] = 0x64f98fa7;
  m_hash[7] = 0xbefa4fa4;
#endif
}


/// add arbitrary number of bytes
void SHA256::add(const void* data, size_t numBytes)
{
  const uint8_t* current = (const uint8_t*) data;

  if (m_bufferSize > 0)
  {
    while (numBytes > 0 && m_bufferSize < BlockSize)
    {
      m_buffer[m_bufferSize++] = *current++;
      numBytes--;
    }
  }

  // full buffer
  if (m_bufferSize == BlockSize)
  {
    sha256_compress(m_buffer, m_hash);
    m_numBytes  += BlockSize;
    m_bufferSize = 0;
  }

  // no more data ?
  if (numBytes == 0)
    return;

  // process full blocks
  while (numBytes >= BlockSize)
  {
    sha256_compress(current, m_hash);
    current    += BlockSize;
    m_numBytes += BlockSize;
    numBytes   -= BlockSize;
  }

  // keep remaining bytes in buffer
  while (numBytes > 0 && m_bufferSize < BlockSize)
  {
    m_buffer[m_bufferSize++] = *current++;
    numBytes--;
  }
}


/// process final block, less than 64 bytes
void SHA256::processBuffer()
{
  // the input bytes are considered as bits strings, where the first bit is the most significant bit of the byte

  // - append "1" bit to message
  // - append "0" bits until message length in bit mod 512 is 448
  // - append length as 64 bit integer

  // number of bits
  size_t paddedLength = m_bufferSize * 8;

  // plus one bit set to 1 (always appended)
  paddedLength++;

  // number of bits must be (numBits % 512) = 448
  size_t lower11Bits = paddedLength & 511;
  if (lower11Bits <= 448)
    paddedLength +=       448 - lower11Bits;
  else
    paddedLength += 512 + 448 - lower11Bits;
  // convert from bits to bytes
  paddedLength /= 8;

  // only needed if additional data flows over into a second block
  unsigned char extra[BlockSize];

  // append a "1" bit, 128 => binary 10000000
  if (m_bufferSize < BlockSize)
    m_buffer[m_bufferSize] = 128;
  else
    extra[0] = 128;

  size_t i;
  for (i = m_bufferSize + 1; i < BlockSize; i++)
    m_buffer[i] = 0;
  for (; i < paddedLength; i++)
    extra[i - BlockSize] = 0;

  // add message length in bits as 64 bit number
  uint64_t msgBits = 8 * (m_numBytes + m_bufferSize);
  // find right position
  unsigned char* addLength;
  if (paddedLength < BlockSize)
    addLength = m_buffer + paddedLength;
  else
    addLength = extra + paddedLength - BlockSize;

  // must be big endian
  *addLength++ = (unsigned char)((msgBits >> 56) & 0xFF);
  *addLength++ = (unsigned char)((msgBits >> 48) & 0xFF);
  *addLength++ = (unsigned char)((msgBits >> 40) & 0xFF);
  *addLength++ = (unsigned char)((msgBits >> 32) & 0xFF);
  *addLength++ = (unsigned char)((msgBits >> 24) & 0xFF);
  *addLength++ = (unsigned char)((msgBits >> 16) & 0xFF);
  *addLength++ = (unsigned char)((msgBits >>  8) & 0xFF);
  *addLength   = (unsigned char)( msgBits        & 0xFF);

  // process blocks
  sha256_compress(m_buffer, m_hash);
  // flowed over into a second block ?
  if (paddedLength > BlockSize)
    sha256_compress(extra, m_hash);
}


/// return latest hash as 64 hex characters
std::string SHA256::getHash()
{
  // compute hash (as raw bytes)
  unsigned char rawHash[HashBytes];
  getHash(rawHash);

  // convert to hex string
  std::string result;
  result.reserve(2 * HashBytes);
  for (int i = 0; i < HashBytes; i++)
  {
    static const char dec2hex[16+1] = "0123456789abcdef";
    result += dec2hex[(rawHash[i] >> 4) & 15];
    result += dec2hex[ rawHash[i]       & 15];
  }

  return result;
}


/// return latest hash as bytes
void SHA256::getHash(unsigned char buffer[SHA256::HashBytes])
{
  // save old hash if buffer is partially filled
  uint32_t oldHash[HashValues];
  for (int i = 0; i < HashValues; i++)
    oldHash[i] = m_hash[i];

  // process remaining bytes
  processBuffer();

  unsigned char* current = buffer;
  for (int i = 0; i < HashValues; i++)
  {
    *current++ = (m_hash[i] >> 24) & 0xFF;
    *current++ = (m_hash[i] >> 16) & 0xFF;
    *current++ = (m_hash[i] >>  8) & 0xFF;
    *current++ =  m_hash[i]        & 0xFF;

    // restore old hash
    m_hash[i] = oldHash[i];
  }
}


/// compute SHA256 of a memory block
std::string SHA256::operator()(const void* data, size_t numBytes)
{
  reset();
  add(data, numBytes);
  return getHash();
}


/// compute SHA256 of a string, excluding final zero
std::string SHA256::operator()(const std::string& text)
{
  reset();
  add(text.c_str(), text.size());
  return getHash();
}
