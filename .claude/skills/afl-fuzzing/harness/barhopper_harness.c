/* AFL fuzzing harness for libbarhopper_v3.so (Google ML Kit barcode/QR recognizer)
 * Reachability: a malicious QR/barcode image scanned by a ticket-scanner app
 * flows into BarhopperV3.recognizeBufferNative as a luminance buffer.
 *
 * Strategy: call the REAL exported JNI function with a stub JNIEnv.
 *   - createNative(env, cls)  -> allocates a 104-byte recognizer context (no args, no model)
 *   - recognizeBufferNative(env, this, ctx, W, H, byteBufferObj, arg4)
 *       reads the image via env->GetDirectBufferAddress (vtable idx 230 / off 0x730)
 * We fix W,H and allocate the image buffer at EXACTLY W*H (guarded by libdislocator),
 * so any out-of-bounds access on a hostile image at valid geometry faults => real bug.
 * JNI result-delivery calls are absorbed by a generic stub (rarely hit on random input).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>

#ifndef IMG_W
#define IMG_W 256
#endif
#ifndef IMG_H
#define IMG_H 256
#endif
#define IMG_SIZE ((size_t)IMG_W * (size_t)IMG_H)
#ifndef REALALLOC
#define REALALLOC IMG_SIZE   /* actual bytes allocated for the image buffer */
#endif
#ifndef CLAIM_W
#define CLAIM_W IMG_W
#endif
#ifndef CLAIM_H
#define CLAIM_H IMG_H
#endif

static void  *g_img = NULL;      /* fuzzed luminance buffer, exactly IMG_SIZE bytes */
static size_t g_img_cap = 0;

/* generic JNIEnv method: return a pointer to zeroed scratch so object-returning
 * calls in the (rarely reached) result path don't NULL-deref. */
static char g_scratch[8192];
static intptr_t jni_generic(void) { return (intptr_t)g_scratch; }
static void*    jni_GetDirectBufferAddress(void *env, void *buf){ (void)env;(void)buf; return g_img; }
static intptr_t jni_GetDirectBufferCapacity(void *env, void *buf){ (void)env;(void)buf; return (intptr_t)g_img_cap; }

static void *g_table[400];
static void *g_tableptr;

typedef long (*createNative_t)(void *env, void *clazz);
typedef void (*recognizeBuffer_t)(void *env, void *thiz, long ctx,
                                  int w, int h, void *bufobj, void *arg4);

int main(int argc, char **argv) {
  if (argc < 2) { fprintf(stderr, "usage: %s <input>\n", argv[0]); return 2; }

  void *lib = dlopen("libbarhopper_v3.so", RTLD_NOW | RTLD_GLOBAL);
  if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
  createNative_t createNative = (createNative_t)dlsym(lib,
      "Java_com_google_android_libraries_barhopper_BarhopperV3_createNative");
  recognizeBuffer_t recog = (recognizeBuffer_t)dlsym(lib,
      "Java_com_google_android_libraries_barhopper_BarhopperV3_recognizeBufferNative");
  if (!createNative || !recog) {
    fprintf(stderr, "dlsym: create=%p recog=%p\n", (void*)createNative, (void*)recog);
    return 2;
  }

  for (int i = 0; i < 400; i++) g_table[i] = (void*)jni_generic;
  g_table[230] = (void*)jni_GetDirectBufferAddress;
  g_table[231] = (void*)jni_GetDirectBufferCapacity;
  g_tableptr = g_table;
  void *env = &g_tableptr;

  long ctx = createNative(env, NULL);

  FILE *f = fopen(argv[1], "rb");
  if (!f) return 0;
  static uint8_t in[1 << 20];
  size_t n = fread(in, 1, sizeof(in), f);
  fclose(f);

  char dummy_this[64];  memset(dummy_this, 0, sizeof dummy_this);
  char arg4[4096];      memset(arg4, 0, sizeof arg4);

  g_img_cap = (size_t)CLAIM_W * (size_t)CLAIM_H;   /* capacity reported to the lib */
  size_t real_alloc = (size_t)REALALLOC;
  g_img = malloc(real_alloc);           /* real buffer (may be < claimed) — libdislocator guards its tail */
  if (!g_img) return 0;
  memset(g_img, 0, real_alloc);
  memcpy(g_img, in, n < real_alloc ? n : real_alloc);

  recog(env, dummy_this, ctx, CLAIM_W, CLAIM_H, (void*)1, arg4);

  free(g_img);
  return 0;
}
