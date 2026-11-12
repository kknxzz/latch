#ifndef LATCH_CRYPTO_H
#define LATCH_CRYPTO_H
#include <stdint.h>
#include <stddef.h>

typedef struct { uint8_t *data; size_t len; } latch_buffer;
/* Return codes: 0 success, 1 invalid input, 2 invalid state, 3 membership
 * mismatch, 4 crypto rejection, 5 native panic. All failures contain no payload. */
int32_t latch_session_new(const uint8_t*, size_t, const uint8_t*, size_t,
                         const uint8_t*, size_t, uint64_t*);
/* Operations: 1 keypackage, 2 create, 3 join, 4 add, 5 remove, 6 update,
 * 7 process commit, 8 encrypt, 9 decrypt, 10 roster, 11 epoch.
 * Compound arguments/results are uint32-big-endian-length-prefixed fields.
 * Membership failures invalidate the session. Buffers are borrowed until return.
 * Every successful result must be freed exactly once using latch_buffer_free. */
int32_t latch_execute(uint64_t, uint32_t, const uint8_t*, size_t, latch_buffer*);
int32_t latch_session_free(uint64_t);
void latch_buffer_free(latch_buffer);
#endif
