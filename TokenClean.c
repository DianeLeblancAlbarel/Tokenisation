
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

#define aesSize 256
#define HASH_LENGTH 2*SHA224_DIGEST_LENGTH+1

#define TIMEFRAME 0.1
#define LIFESPAN 10000
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

static const uint8_t zero_row[ROW_BYTES] = { 0 };


// CODE TAKEN FROM https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
void handleErrors(void){
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext){
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext){
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

// OUR CODE


TIME_T get_time(struct timeval t){
        double sum;
        uint64_t seconds = t.tv_sec;
    uint64_t microseconds = t.tv_usec;
        sum = seconds + microseconds*1e-6; //1e-6 over integers ? mayber float or double instead
        return sum;
}

double get_time_execution(struct timeval begin, struct timeval end){
        double sum;
        long seconds = end.tv_sec - begin.tv_sec;
    long microseconds = end.tv_usec - begin.tv_usec;
        sum = seconds + microseconds*1e-6;
        return sum;
}

int tokenisation(uint8_t *table, CARD_T cb, USES_T uses, TIME_T deadline, PK_T pk, TOKEN_T *tokenToReturn, unsigned char key[32], unsigned char iv[16]){
        uint8_t buffer[4];
        uint8_t hash[HASH_LENGTH];
        TOKEN_T token;

        int timepast = 0;
        struct timeval begin, end;
        double delta;

    uint32_t random = -1;

        uint8_t row[ROW_BYTES] = { 0 };
        memcpy(row, &cb, 8);
        memcpy(row+12, &uses, 1);
        memcpy(row+13, &deadline, 8);
        memcpy(row+21, &pk,8);

        gettimeofday(&begin,0);

        do{
                do{
            RAND_bytes(buffer, RANDBYTES);
                memcpy(row+8, buffer, 4);
            SHA224((const unsigned char *)row, ROW_BYTES, hash);
                memcpy(&random, hash,4);
                }while(random > 0b11111010010101101110101000000000  );

            token = random % NUM_ROWS;
            gettimeofday(&end,0);
            delta = get_time_execution(begin,end);
        }while ( memcmp (zero_row, table + token*ROW_BYTES, 8) && delta<TIMEFRAME);

        if ( !memcmp(zero_row, table+token*ROW_BYTES, 8)){

                int ctlen;
        ctlen = encrypt (row, 31, key, iv, table+token*ROW_BYTES);

            *tokenToReturn = token;
                return 1;// one for success
        }
        else{
            return 0;// zero for failure
        }
}

int cardIsValid(CARD_T card){
        return (int) card;
}

void clean(uint8_t * row, uint8_t * table, unsigned char key[32], unsigned char iv[16]){
    struct timeval tdays;
    gettimeofday(&tdays,0);
    TIME_T now = get_time(tdays);
        TIME_T expiry;

        uint8_t hash[HASH_LENGTH];
        TOKEN_T token;

        if(memcmp(zero_row, row, 32)){

                unsigned char drow[32];
            decrypt(row, 32, key, iv, drow);
                memcpy(&expiry, drow+13, 8);

            SHA224((const unsigned char *)row, ROW_BYTES, hash);
            token =((* (uint32_t *)hash)) % NUM_ROWS;

                if ( !memcmp(zero_row, drow+12,1)  || expiry < now || cardIsValid((CARD_T) drow[0]) || (row == table+token*ROW_BYTES) ){
                        memset(row, 0, ROW_BYTES);
                }
        }
}

void cleanTable(uint8_t *table, unsigned char key[32], unsigned char iv[16] ){
    for (uint64_t i=0; i<NUM_ROWS; i++)
        clean(table+i*ROW_BYTES, table, key, iv);
}

int signatureIsValid(PK_T * pk, SIGN_T * signature){
        return !memcmp(pk,signature,8);
}

void detokenisation(uint8_t *table, TOKEN_T token, CARD_T * card, SIGN_T * signature, unsigned char key[32], unsigned char iv[16] ){
    struct timeval tempTime;
    gettimeofday(&tempTime,0);
    TIME_T now = get_time(tempTime);
        TIME_T expiry;
        uint8_t * row = table+token*ROW_BYTES;

        uint8_t drow[32];
    decrypt(row, 32, key, iv, drow);

        memcpy(&expiry, drow+13, 8);
    if( memcmp(zero_row, drow+12,1) && expiry > now && signatureIsValid((PK_T *) drow+21, signature) ) { //token is valid
        memcpy(card, drow, 8);

                if ( row[12] > 1 )
             row[12] --;
        else{
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

int main(){
        printf("Token Vault Started\n");

        struct timeval begin,end,t;
        time_t tt;
        clock_t firstToken=0, lastToken=0, sumToken=0, tempTime, cleanTime,temp;
        double first, last, mean;

        CARD_T cb;
        SIGN_T pk;

        unsigned char key[32];
        unsigned char iv[16];

        RAND_bytes(key, 32);
        RAND_bytes(iv,16);
        unsigned long long size = (unsigned long )NUM_ROWS * (unsigned long long)ROW_BYTES;

        uint8_t * table=calloc(size,sizeof(uint8_t));
        TOKEN_T token;
        int try;

        gettimeofday(&begin,0);
        gettimeofday(&t,0);
        TIME_T expiry = get_time(t) + LIFESPAN;

        for (int i = 0; i<NUM_ROWS; i++){
            printf("%d\n",i);
            cb = i;
            pk = i;
            if(i==0){
                temp=clock();
                tempTime = clock();
                
                try = tokenisation(table, cb, MAXUSES, expiry,pk, &token, key, iv);
                
                sumToken += clock() - tempTime;
                firstToken = clock()-temp;
            }
            else {
                temp=clock();
                tempTime = clock();
                try = tokenisation(table, cb, MAXUSES, expiry,pk, &token, key, iv);
                sumToken += clock() - tempTime;
                lastToken=clock()-temp;
            }
            if(try==0){
                printf("BREAK\n"); // Expé fill until fail
                break;
            }
        }
        gettimeofday(&end,0);
        printf("TOKENS CREATED\n");

        uint64_t numberInsert = 1;
        for(uint64_t i=0; i<NUM_ROWS; i++){
            if(memcmp(zero_row,table+i*ROW_BYTES,8)) numberInsert++; //if not zero, increment
        }

        printf("TOKENS counted\n");


        mean = ((double)sumToken/CLOCKS_PER_SEC)/numberInsert;
        first = (double)firstToken/CLOCKS_PER_SEC;
        last = (double)lastToken/CLOCKS_PER_SEC;

        printf("clocks set\n");

        cleanTime = clock();
        cleanTable(table, key, iv);
        cleanTime = clock() - cleanTime;


        printf("table cleaned\n");

        FILE *fp;
        fp = fopen("time.txt", "a+");

            if(fp == NULL){
                printf("Error opening file\n");
                exit(1);
            }
                else{
                        fprintf(fp,"total: %f, mean : %f, first : %f, last %f, number insert : %lld size : %d clean time : %f\n", get_time_execution(begin,end), mean, first, last,(long long int) numberInsert,NUM_ROWS, (double)cleanTime/CLOCKS_PER_SEC);
                        fclose(fp);
                }

        printf("total: %f, mean : %f, first : %f, last %f\n", get_time_execution(begin,end), mean, first, last);

}
