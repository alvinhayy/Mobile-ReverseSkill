#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
// Deliberately buggy parser to validate the AFL-on-emulator pipeline.
static void parse(const uint8_t *d, long n) {
  char buf[16];
  if (n >= 4 && d[0]=='F' && d[1]=='U' && d[2]=='Z' && d[3]=='Z') {
    // length byte drives a memcpy into a fixed 16-byte stack buffer -> overflow
    long len = (n >= 5) ? d[4] : 0;
    if (n >= 5 + len) memcpy(buf, d + 5, len);  // BUG: no bound check vs sizeof(buf)
    volatile char sink = buf[0]; (void)sink;
  }
}
int main(int argc, char **argv){
  if (argc < 2) return 0;
  FILE *f = fopen(argv[1], "rb"); if(!f) return 0;
  static uint8_t data[1<<16];
  long n = fread(data, 1, sizeof(data), f); fclose(f);
  parse(data, n);
  return 0;
}
