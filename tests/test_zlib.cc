#include <iostream>
#include <iomanip>
#include <cstring>
#include <zlib.h>

// Compresses a char array using gzip
bool compressString(const char* input, size_t inputLength, std::string &output) {
  z_stream zs;
  memset(&zs, 0, sizeof(zs));

  if (deflateInit2(&zs, Z_BEST_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
    return false;
  }

  zs.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(input));
  zs.avail_in = inputLength;

  int ret;
  char outbuffer[32768];
  std::string outstring;

  do {
    zs.next_out = reinterpret_cast<Bytef*>(outbuffer);
    zs.avail_out = sizeof(outbuffer);

    ret = deflate(&zs, Z_FINISH);

    if (outstring.size() < zs.total_out) {
      outstring.append(outbuffer, zs.total_out - outstring.size());
    }
  } while (ret == Z_OK);

  deflateEnd(&zs);

  if (ret != Z_STREAM_END) {
    return false;
  }

  output = outstring;
  return true;
}

// Decompresses a gzip-compressed char array
bool decompressString(const char* input, size_t inputLength, std::string &output) {
  z_stream zs;
  memset(&zs, 0, sizeof(zs));

  if (inflateInit2(&zs, 15 + 16) != Z_OK) {
    return false;
  }

  zs.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(input));
  zs.avail_in = inputLength;

  int ret;
  char outbuffer[32768];
  std::string outstring;

  do {
    zs.next_out = reinterpret_cast<Bytef*>(outbuffer);
    zs.avail_out = sizeof(outbuffer);

    ret = inflate(&zs, 0);

    if (outstring.size() < zs.total_out) {
      outstring.append(outbuffer, zs.total_out - outstring.size());
    }
  } while (ret == Z_OK);

  inflateEnd(&zs);

  if (ret != Z_STREAM_END) {
    return false;
  }

  output = outstring;
  return true;
}

int main() {
  //const char* original = "Hello, World! This is a test string to demonstrate gzip compression and decompression using zlib in C++.";
  const char *original = "foo";
  size_t originalLength = strlen(original);

  std::string compressed;
  std::string decompressed;

  if (compressString(original, originalLength, compressed)) {
    std::cout << "Compression successful!\n";
  } else {
    std::cerr << "Compression failed.\n";
    return 1;
  }

  for (size_t i = 0; i < compressed.size(); ++i) {
    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)compressed[i];
  }
  std::cout << std::dec << std::endl;
  if (decompressString(compressed.c_str(), compressed.size(), decompressed)) {
    std::cout << "Decompression successful!\n";
    std::cout << "Decompressed string: " << decompressed << "\n";
  } else {
    std::cerr << "Decompression failed.\n";
    return 1;
  }

  return 0;
}

