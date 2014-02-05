// //////////////////////////////////////////////////////////
// digest.cpp
// Copyright (c) 2014 Stephan Brumme. All rights reserved.
// see http://create.stephan-brumme.com/disclaimer.html
//

#include "crc32.h"
#include "md5.h"
#include "sha1.h"
#include "sha256.h"

#include <iostream>
#include <fstream>

int main(int argc, char** argv)
{
  // syntax check
  if (argc < 2 || argc > 3)
  {
    std::cout << "./digest filename [--md5|--sha1|--sha256|--crc]" << std::endl;
    return 1;
  }

  // parameters
  std::string filename  = argv[1];
  std::string algorithm = argc == 3 ? argv[2] : "";
  bool computeCrc32  = algorithm.empty() || algorithm == "--crc";
  bool computeMd5    = algorithm.empty() || algorithm == "--md5";
  bool computeSha1   = algorithm.empty() || algorithm == "--sha1";
  bool computeSha256 = algorithm.empty() || algorithm == "--sha256";

  const size_t BufferSize = 1024*1024;
  char* buffer = new char[BufferSize];

  CRC32  digestCrc32;
  MD5    digestMd5;
  SHA1   digestSha1;
  SHA256 digestSha256;

  // open file
  std::ifstream file(filename.c_str(), std::ios::in | std::ios::binary);
  if (!file)
  {
    std::cerr << "Can't open '" << filename << "'" << std::endl;
    return 2;
  }

  while (!file.eof())
  {
    file.read(buffer, BufferSize);
    std::streamsize numBytesRead = file.gcount();

    if (computeCrc32)
      digestCrc32 .add(buffer, numBytesRead);
    if (computeMd5)
      digestMd5   .add(buffer, numBytesRead);
    if (computeSha1)
      digestSha1  .add(buffer, numBytesRead);
    if (computeSha256)
      digestSha256.add(buffer, numBytesRead);
  }
  file.close();
  delete[] buffer;

  if (computeCrc32)
    std::cout << "CRC32:  " << digestCrc32 .getHash() << std::endl;
  if (computeMd5)
    std::cout << "MD5:    " << digestMd5   .getHash() << std::endl;
  if (computeSha1)
    std::cout << "SHA1:   " << digestSha1  .getHash() << std::endl;
  if (computeSha256)
    std::cout << "SHA256: " << digestSha256.getHash() << std::endl;

  return 0;
}
