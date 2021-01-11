#ifndef TOKEN_DEF
#define TOKEN_DEF

#include <string.h>
#include <stdint.h>
#include <time.h>
#include <signal.h>
#include <sys/time.h>
#include <unistd.h>
#include <math.h>
#include <pthread.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define HASH_LENGTH 2*SHA224_DIGEST_LENGTH+1

#define TIMEFRAME 0.1
#define LIFESPAN 10000000
#define MAXUSES 3
#define ROW_BYTES 32
#define NUM_ROWS  100000000
#define RANDBYTES 4

#define CARD_T uint64_t
#define RAND_T uint32_t
#define USES_T uint8_t
#define TIME_T uint64_t
#define TOKEN_T uint32_t
#define SIGN_T uint64_t
#define PK_T uint64_t

#define RED   "\x1B[31m"
#define GRN   "\x1B[32m"
#define YEL   "\x1B[33m"
#define BLU   "\x1B[34m"
#define MAG   "\x1B[35m"
#define CYN   "\x1B[36m"
#define WHT   "\x1B[37m"
#define RESET "\x1B[0m"

static const uint8_t zero_row[ROW_BYTES] = { 0 };

int tokenization(uint8_t *table, CARD_T cb, USES_T uses, TIME_T deadline, PK_T  pk, TOKEN_T *tokenToReturn, unsigned char key[32], unsigned char iv[16], int *numberTry);
//returns 1 in case of success, 0 otherwise

void detokenization(uint8_t *table, TOKEN_T token, CARD_T * card, SIGN_T signature, unsigned char key[32], unsigned char iv[16]);

void clean(uint8_t * row, uint8_t * table, unsigned char key[32], unsigned char iv[16]);

void cleanTable(uint8_t *table, unsigned char key[32], unsigned char iv[16] );

void updateKey(uint8_t *table, unsigned char oldKey[32], unsigned char oldiv[16], unsigned char newKey[32], unsigned char newiv[16]);

#endif
