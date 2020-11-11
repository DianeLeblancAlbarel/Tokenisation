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

#define RANDBYTES 4

#define CARD_T uint64_t
#define RAND_T uint32_t
#define USES_T uint8_t
#define TIME_T uint64_t
#define TOKEN_T uint32_t

static const uint8_t zero_row[ROW_BYTES] = { 0 };
int NUM_ROWS =90000000;

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

int tokenisation(uint8_t *table, CARD_T cb, USES_T uses, TIME_T deadline, TOKEN_T *tokenToReturn, unsigned char key[32], unsigned char iv[16]){
        uint8_t buffer[4];
        uint8_t hash[HASH_LENGTH]; // verif size
        TOKEN_T token;

        int timepast = 0;
        struct timeval begin, end;
        double delta;

        uint8_t row[ROW_BYTES] = { 0 };
        memcpy(row, &cb, 8);
        memcpy(row+12, &uses, 1);
        memcpy(row+13, &deadline, 8);

        gettimeofday(&begin,0);

        do{
            RAND_bytes(buffer, RANDBYTES);
                memcpy(row+8, buffer, 4);

            SHA224((const unsigned char *)row, ROW_BYTES, hash); //verifier la taille de hash?
            token =((* (uint32_t *)hash)) % NUM_ROWS;

            gettimeofday(&end,0);
            delta = get_time_execution(begin,end);
        }while ( memcmp (zero_row, table + token*ROW_BYTES, 8) && delta<TIMEFRAME);

        if ( !memcmp(zero_row, table+token*ROW_BYTES, 8)){
//          memcpy(table+token*ROW_BYTES, &row, ROW_BYTES);

                int ctlen;
        ctlen = encrypt (row, 31, key, iv, table+token*ROW_BYTES);
//              printf("ctlen = %d ",ctlen);

            *tokenToReturn = token;
//      printf("Token %d created successfully \n",token);
                return 1;// one for success
        }
        else{
//      printf("Token creation failed \n");
            return 0;// zero for failure
        }

        free(hash);
}

void clean(uint8_t * row, unsigned char key[32], unsigned char iv[16]){
    struct timeval tdays;
    gettimeofday(&tdays,0);
    TIME_T now = get_time(tdays);
        TIME_T expiry;

//      printf("cleaning\n");

        if(memcmp(zero_row, row, 32)){

                unsigned char drow[32];
            decrypt(row, 32, key, iv, drow);
                memcpy(&expiry, drow+13, 8);

           if ( !memcmp(zero_row, drow+12,1)  || expiry < now){ // Add CB cheksum and hash for address
               memset(row, 0, ROW_BYTES);
           }
        }
}

void cleanTable(uint8_t *table, unsigned char key[32], unsigned char iv[16] ){
    for (int i=0;i<NUM_ROWS;i++)
        clean(table+i*ROW_BYTES, key, iv);
}

void detokenisation(uint8_t *table, TOKEN_T token, CARD_T *card, unsigned char key[32], unsigned char iv[16] ){
    struct timeval tempTime;
    gettimeofday(&tempTime,0);
    TIME_T now = get_time(tempTime);
        TIME_T expiry;
        uint8_t * row = table+token*ROW_BYTES;

        uint8_t drow[32];
    decrypt(row, 32, key, iv, drow);

        memcpy(&expiry, drow+13, 8);
    if( !memcmp(zero_row, drow+12,1) && expiry > now ){ //token is valid
        memcpy(card, drow, 8);

                if ( row[12] > 1 )
             row[12] --;
        else{
            printf("Maximal number of uses reached, cleaning token\n");
            clean(row, key, iv);
        }
    }
    else{
        printf("Token is invalid or obsolete\n");
        clean(row, key, iv);
        exit(1);
    }

}
void print_usage(char *argv[]) {
	printf("usage: %s [-r <val>] \n", argv[0]);
	exit(EXIT_FAILURE);

}

int main(int argc, char *argv[]){
    char opt;
    //NUM_ROWS=0;
    printf("NUM_ROW = %d\n",NUM_ROWS);
        struct timeval t;
        time_t tt;
        clock_t firstToken,temp, lastToken, sumToken=0, tempTime, cleanTime;
        double first, last, mean;

        CARD_T cb;

        unsigned char key[32];
        unsigned char iv[16];

        RAND_bytes(key, 32);
        RAND_bytes(iv,16);
        
        uint8_t * table= malloc(NUM_ROWS * ROW_BYTES*sizeof(uint8_t));
        
        TOKEN_T token;
        int try;

        gettimeofday(&t,0);
        TIME_T expiry = get_time(t) + LIFESPAN;

        for (int i = 0; i<NUM_ROWS; i++){ // en fonction de l'expé
            cb = i;
            if(i==0){
                temp=clock();
                tempTime = clock();
                
                try = tokenisation(table, cb, MAXUSES, expiry, &token, key, iv);
                
                sumToken += clock() - tempTime;
                firstToken = clock()-temp;
            }
            else if (i <NUM_ROWS-1 ){
                tempTime = clock();
                try = tokenisation(table, cb, MAXUSES, expiry, &token, key, iv);
                sumToken += clock() - tempTime;
            }
            else{
                printf("LAST\n");
                temp=clock();
                tempTime = clock();
                try = tokenisation(table, cb, MAXUSES, expiry, &token, key, iv);
                sumToken += clock() - tempTime;
                lastToken=clock()-temp;
            }
            if(try==0){
                printf("BREAK\n"); // Expé fill until fail
                break;
            }
        }

        printf("TOKENS CREATED\n");

        uint64_t numberInsert = 0;
        for(int i=0; i<NUM_ROWS; i++){
            if(memcmp(zero_row,table+i*ROW_BYTES,8)) numberInsert++; //if not zero, increment
        }

        printf("TOKENS counted\n");


        mean = ((double)sumToken/CLOCKS_PER_SEC)/NUM_ROWS;
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
                        fprintf(fp,"total: %f, mean : %f, first : %f, last %f, number insert : %lld size : %d clean time : %f\n", (double) sumToken/CLOCKS_PER_SEC, mean, first, last,(long long int) numberInsert,NUM_ROWS, (double)cleanTime/CLOCKS_PER_SEC);
                        fclose(fp);
                }

        printf("total: %f, mean : %f, first : %f, last %f\n", (double) sumToken/CLOCKS_PER_SEC, mean, first, last);
    free(table);

}

