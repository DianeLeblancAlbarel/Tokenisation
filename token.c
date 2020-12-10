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
#include "tools.h"
#include "token.h"

#define HASH_LENGTH 2*SHA224_DIGEST_LENGTH+1

#define TIMEFRAME 0.1
#define LIFESPAN 10000
#define MAXUSES 3
#define ROW_BYTES 32
#define NUM_ROWS  10000
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

// Upycling Token Table

int tokenization(uint8_t *table, CARD_T cb, USES_T uses, TIME_T deadline, PK_T  pk, TOKEN_T *tokenToReturn, unsigned char key[32], unsigned char iv[16]){
    uint8_t buffer[4];
    uint8_t hash[HASH_LENGTH];
    TOKEN_T token;
    uint32_t random = -1;

    int timepast = 0;
    struct timeval begin, end;
    double delta;
    gettimeofday(&begin,0);

    uint8_t row[ROW_BYTES] = { 0 };
    memcpy(row, &cb, 8);
    memcpy(row+12, &uses, 1);
    memcpy(row+13, &deadline, 8);
    memcpy(row+21, &pk,8);

    do{
        do{
            RAND_bytes(buffer, RANDBYTES);
            memcpy(row+8, buffer, 4);
            SHA224((const unsigned char *)row, ROW_BYTES, hash);
            memcpy(&random, hash,4);
        } while(random > 0b11111010010101101110101000000000);
        token = random % NUM_ROWS;

        gettimeofday(&end,0);
        delta = get_time_execution(begin,end);
    } while ( memcmp (zero_row, table + token*ROW_BYTES, 8) && delta<TIMEFRAME);

    if ( !memcmp(zero_row, table+token*ROW_BYTES, 8)){
        encrypt (row, 31, key, iv, table+token*ROW_BYTES);
        *tokenToReturn = token;
        return 1;  
    }
    else return 0; 
}

void detokenization(uint8_t *table, TOKEN_T token, CARD_T * card, SIGN_T signature, unsigned char key[32], unsigned char iv[16] ){
    struct timeval tempTime;
    gettimeofday(&tempTime,0);
    TIME_T now = get_time(tempTime);
    TIME_T expiry;
    uint8_t * row = table+token*ROW_BYTES;

    uint8_t drow[32];
    decrypt(row, 32, key, iv, drow);
    
    memcpy(&expiry, drow+13, 8);
    if( memcmp(zero_row, drow+12,1) && expiry > now && signatureIsValid((PK_T *) drow+21, &signature) ) { //token is valid
        memcpy(card, drow, 8);
        if (drow[12] > 1 ){
            drow[12] --;
            printf("This token can be used again");
            encrypt(drow,31,key,iv,row);
        }
        else{
            drow[12] --;
            encrypt(drow,31,key,iv,row);
            printf("Maximal number of uses reached, cleaning token\n");
            clean(row, table, key, iv);
        }
    }
    else{
        printf("Token is invalid or obsolete\n");
        clean(row, table, key, iv);
        exit(1);
    }
}

void clean(uint8_t * row, uint8_t * table, unsigned char key[32], unsigned char iv[16]){
    struct timeval tdays;
    gettimeofday(&tdays,0);
    TIME_T now = get_time(tdays);
    TIME_T expiry;
    CARD_T card;
    TOKEN_T token;
    RAND_T random;
    uint8_t hash[HASH_LENGTH];

    if(memcmp(zero_row, row, 32)){
        unsigned char drow[32];
        decrypt(row, 32, key, iv, drow);

        uint8_t hrow[ROW_BYTES] = { 0 };
        memcpy(hrow, drow, 12);
        memcpy(hrow+13, drow +13, 16);

        SHA224((const unsigned char *)row, ROW_BYTES, hash);
        memcpy(&random, hash,4);
        token = random % NUM_ROWS;
        memcpy(&card, drow,8);
        memcpy(&expiry, drow+13, 8);

        if ( !memcmp(zero_row, drow+12,1)  || expiry < now || !cardIsValid(card) || (row == table+token*ROW_BYTES) ) memset(row, 0, ROW_BYTES);
    }
}

void cleanTable(uint8_t *table, unsigned char key[32], unsigned char iv[16] ){
    for (uint64_t i=0; i<NUM_ROWS; i++) clean(table+i*ROW_BYTES, table, key, iv);
}

void updateKey(uint8_t *table, unsigned char oldKey[32], unsigned char oldiv[16], unsigned char newKey[32], unsigned char newiv[16]){
    uint8_t * row;
    uint8_t drow[32];
    for (int i = 0;i<NUM_ROWS;i++){
        row = table + i*ROW_BYTES;
        if(memcmp(zero_row,row,32)){
            decrypt(row,32,oldKey,oldiv,drow);
            encrypt(drow, 31, newKey, newiv, table+i*ROW_BYTES);
        }
    }
}
