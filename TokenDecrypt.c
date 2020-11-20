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

TIME_T get_time(struct timeval t){
        double sum;
        uint64_t seconds = t.tv_sec;
    uint64_t microseconds = t.tv_usec;
        sum = seconds + microseconds*1e-6;
        return sum;
}

double get_time_execution(struct timeval begin, struct timeval end){
        double sum;
        long seconds = end.tv_sec - begin.tv_sec;
    long microseconds = end.tv_usec - begin.tv_usec;
        sum = seconds + microseconds*1e-6;
        return sum;
}

int tokenization(uint8_t *table, CARD_T cb, USES_T uses, TIME_T deadline, PK_T  pk, TOKEN_T *tokenToReturn, unsigned char key[32], unsigned char iv[16]){
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
        return 1;// success
    }
    else{
        return 0;// failure
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

uint32_t count_tokens(uint8_t *table){
        uint32_t res = 0;
        for(uint32_t i = 0;i<NUM_ROWS;i++){
                if(memcmp(zero_row,table+i*ROW_BYTES,ROW_BYTES))
                        res ++;
    }
        return res;
}

void print_expiracy(unsigned long long seconds){
    unsigned long long days = seconds / (24*3600);
    seconds -= days * 24 * 3600;
    unsigned long long hours = seconds / 3600;
    seconds -= hours * 3600;
    unsigned long long minutes = seconds / 60;
    seconds -= minutes * 60;
    printf("  Expiracy in %lld days, %lld hours, %lld minutes and %lld seconds\n", days, hours, minutes, seconds);
}

void print_CB(CARD_T CB) {
    unsigned long long CB1 = CB % (unsigned long long) pow(10,4);
    unsigned long long CB2 = (CB / (unsigned long long) pow(10,4)) % (unsigned long long) pow(10,4);
    unsigned long long CB3 = (CB / (unsigned long long) pow(10,8)) % (unsigned long long) pow(10,4);
    unsigned long long CB4 = (CB / (unsigned long long) pow(10,12)) % (unsigned long long) pow(10,4);
    printf(BLU"%lld_%lld_%lld_%lld ***\n" RESET, CB1,CB2,CB3,CB4);
}

void print_row(uint8_t * table, TOKEN_T token, unsigned char key[32], unsigned char iv[16]) {
    uint8_t * row = table+token*ROW_BYTES;
    if(!memcmp(zero_row,row,8)){  printf("The token %d is not in the table!\n",token);}
    else{
        printf("-----------------------------------------------------------\n");
                //decrypt
        uint8_t drow[32];
        decrypt(row, 32, key, iv, drow);

            USES_T usesLeft = drow[12];
        printf("Token %d (%d use", token, usesLeft);
        if(usesLeft > 1){
            printf("s) of the CB ");
        }
        else{
            printf(") of CB ");
        }
            CARD_T card;
            memcpy(&card, drow,8);
        print_CB(card);

        struct timeval t;
        gettimeofday(&t, 0);
        unsigned long long temp = get_time(t);
        unsigned long long seconds;
            TIME_T expiry;
            memcpy(&expiry, drow +13,8);

        if (expiry > temp) seconds = (expiry - temp);
        else{printf("reset"); seconds = 0;}

        print_expiracy(seconds);
            RAND_T ran;
            memcpy(&ran,drow+8,4);
        printf("  (generated with the random %d)\n", ran);
        printf("-----------------------------------------------------------\n\n\n");
    }
}

void print_table(uint8_t * table, TOKEN_T * ListOfTokens, int beg, int end, unsigned char key[32], unsigned char iv[16]) {
    uint32_t  nb = count_tokens(table);
    printf("###########################################################\n");
    printf("#################  TABLE OF %d TOKENS  ###############\n", nb);
    printf("###########################################################\n");
    for (int k = beg ; k < end ; k++) {
        if(memcmp(zero_row,table+ListOfTokens[k]*ROW_BYTES, 8)) print_row(table, ListOfTokens[k], key, iv);
    }
}

int main(){

    struct timeval begin,end,t;
    time_t tt;
    clock_t firstToken=0, lastToken=0, sumToken=0, tempTime, cleanTime, temp;
    double first, last, mean;

    CARD_T cb;
    PK_T pk = 1234;
        SIGN_T sign = 1234;

    unsigned char key[32];
    unsigned char iv[16];

    RAND_bytes(key, 32);
    RAND_bytes(iv,16);
    unsigned long long size = (unsigned long )NUM_ROWS * (unsigned long long)ROW_BYTES;

    uint8_t * table=calloc(size,sizeof(uint8_t));
    int try;

    gettimeofday(&begin,0);
    gettimeofday(&t,0);

    int * FirstTokens = malloc(10 * sizeof(TOKEN_T));
    unsigned char nbUse;
    TOKEN_T token[1];

    for (int i = 0;i<100;i++) {
        tempTime = clock();
        try = tokenization(table,(CARD_T) 4837562834756767+i ,(USES_T) 1 ,(TIME_T) temp+1000, pk, token, key, iv);
        if (i<10) FirstTokens[i] = token[0];
        sumToken += clock() - tempTime;
        //print_row(table,FirstTokens[i],key,iv);
                if(!try){
            printf("BREAK\n");
            break;
        }
    }

        char input;

        uint32_t nbTokenInserted = count_tokens(table);
    float perc = nbTokenInserted*100/NUM_ROWS;
    printf("%d tokens generated (%.2f%c)\n\n", nbTokenInserted, perc, 37);

        print_table(table, FirstTokens,0,5,key,iv);

    do {
        printf("[1] display the first tokens\n");
        printf("[2] display one token\n");
        printf("[3] tokenization\n");
        printf("[4] detokenization\n");
        printf("[5] clean the table\n");
        printf("[6] update key\n");
        printf("[x] quit.\n");
        scanf(" %c", &input);

        if(input == '1') {
            print_table(table, FirstTokens, 0, 5,key,iv);
        }
        if(input == '2') {
            printf("Token: ");
            int tok;
            scanf("%d", &tok);
            print_row(table, tok, key, iv);
        }
        if(input == '3') {
            printf("Tokenization\n\n");
            unsigned long long CB;
            printf("CB number: ");
            scanf("%lld", &CB);
            int nbUse;
            printf("\nNumber of uses: ");
            scanf("%d", &nbUse);
            int t;
            printf("\nExpiracy: ");
            scanf("%d", &t);
            printf("\n");
            int insertion;
            int token;
            struct timeval tt;
            gettimeofday(&tt, 0);
            temp = get_time(tt);
            try = tokenization(table,CB,nbUse,(TIME_T) temp+t, pk, &token, key, iv);
            if (FirstTokens[0] == 0){
                FirstTokens[0] = token;
            }
            if(try) {
                printf("Token added!\n");
                print_row(table, token, key, iv);
            }
            else printf("No token added.\n");
        }
        if(input == '4') {
            printf("Detokenization\n\n");
            CARD_T CB[1];
            TOKEN_T token;
            printf("Token: ");
            scanf("%d", &token);
            detokenization(table, token, CB, sign, key, iv);
            print_row(table, token, key, iv);
            if (!memcmp(zero_row,table+token*ROW_BYTES,ROW_BYTES)) {
                FirstTokens[0] = 0;
            }
        }
        if(input == '5') {
            cleanTable(table,key,iv);
            printf("Table cleaned\n");
        }
                if(input == '6'){

            unsigned char newkey[32];
            unsigned char newiv[16];
            RAND_bytes(key, 32);
            RAND_bytes(iv,16);
                        //updateTable(table,key,iv,newkey,newiv)
                        printf("Update Table TO BE PROGRAMMED\n");

                        //key = newkey
                }
    } while (input != 'x');

  free(FirstTokens);
  free(table);
}

//int main(){
//        printf("Token Vault Started\n");

//        TIME_T expiry = get_time(t) + LIFESPAN;

//        for (int i = 0; i<NUM_ROWS; i++){
//            printf("%d\n",i);
//            cb = i;
//            pk = i;
//            if(i==0){
//                temp=clock();
//                tempTime = clock();

//                try = tokenisation(table, cb, MAXUSES, expiry,pk, &token, key, iv);

//                sumToken += clock() - tempTime;
//                firstToken = clock()-temp;
//            }
//            else {
//                temp=clock();
//                tempTime = clock();
//                try = tokenisation(table, cb, MAXUSES, expiry,pk, &token, key, iv);
//                sumToken += clock() - tempTime;
//                lastToken=clock()-temp;
//            }
//            if(try==0){
//                printf("BREAK\n"); // Expé fill until fail
//                break;
//            }
//        }
//        gettimeofday(&end,0);
//        printf("TOKENS CREATED\n");

//        uint64_t numberInsert = 1;
//        for(uint64_t i=0; i<NUM_ROWS; i++){
//            if(memcmp(zero_row,table+i*ROW_BYTES,8)) numberInsert++; //if not zero, increment
//        }

//        printf("TOKENS counted\n");


//        mean = ((double)sumToken/CLOCKS_PER_SEC)/numberInsert;
//        first = (double)firstToken/CLOCKS_PER_SEC;
//        last = (double)lastToken/CLOCKS_PER_SEC;

//        printf("clocks set\n");

//        cleanTime = clock();
//        cleanTable(table, key, iv);
//        cleanTime = clock() - cleanTime;


//        printf("table cleaned\n");

//        FILE *fp;
//        fp = fopen("time.txt", "a+");

//            if(fp == NULL){
//                printf("Error opening file\n");
//                exit(1);
//            }
//                else{
//                        fprintf(fp,"total: %f, mean : %f, first : %f, last %f, number insert : %lld size : %d clean time : %f\n", get_time_execution(begin,end), mean, first, last,(long long int) numberInsert,NUM_ROWS, (double)cleanTime/CLOCKS_PER_SEC);
//                        fclose(fp);
//                }

//        printf("total: %f, mean : %f, first : %f, last %f\n", get_time_execution(begin,end), mean, first, last);

//}
