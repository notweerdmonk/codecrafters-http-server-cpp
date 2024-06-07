#include <iostream>
#include <iomanip>
#include <cstring>
#include <ctime>
#include <zlib.h>

int compress_string(const char* in, size_t len, std::string &out) {
  int ret;
  char buffer[32768];
  std::string deflated;
  z_stream zs;

  memset(&zs, 0, sizeof(zs));

  if ((ret = deflateInit2(&zs, Z_BEST_COMPRESSION, Z_DEFLATED, MAX_WBITS + 16,
          8, Z_DEFAULT_STRATEGY)) != Z_OK) {
    return ret;
  }

  zs.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in));
  zs.avail_in = len;

  /* Set the MTIME field */
  gz_header gzheader;
  memset(&gzheader, 0, sizeof(gzheader));
  gzheader.time = std::time(nullptr);
  deflateSetHeader(&zs, &gzheader);

  do {
    zs.next_out = reinterpret_cast<Bytef*>(buffer);
    zs.avail_out = sizeof(buffer);

    ret = deflate(&zs, Z_FINISH);

    if (deflated.size() < zs.total_out) {
      deflated.append(buffer, zs.total_out - deflated.size());
    }
  } while (ret == Z_OK);

  deflateEnd(&zs);

  if (ret != Z_STREAM_END) {
    return ret;
  }

  out = deflated;
  return Z_OK;
}

bool decompress_string(const char* in, size_t len, std::string &out) {
  int ret;
  char buffer[32768];
  std::string inflated;
  z_stream zs;

  memset(&zs, 0, sizeof(zs));

  if ((ret = inflateInit2(&zs, MAX_WBITS + 16)) != Z_OK) {
    return ret;
  }

  zs.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in));
  zs.avail_in = len;

  do {
    zs.next_out = reinterpret_cast<Bytef*>(buffer);
    zs.avail_out = sizeof(buffer);

    ret = inflate(&zs, Z_NO_FLUSH);

    if (inflated.size() < zs.total_out) {
      inflated.append(buffer, zs.total_out - inflated.size());
    }
  } while (ret == Z_OK);

  inflateEnd(&zs);

  if (ret != Z_STREAM_END) {
    return ret;
  }

  out = inflated;
  return Z_OK;
}
