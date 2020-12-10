
#include "token.h"

// Crypto functions : https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption

void handleErrors(void){
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext){
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    if(!(ctx = EVP_CIPHER_CTX_new()))                                           handleErrors();
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))          handleErrors();
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) handleErrors();
    ciphertext_len = len;
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))                   handleErrors();
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext){
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    if(!(ctx = EVP_CIPHER_CTX_new()))                                            handleErrors();
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))           handleErrors();
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) handleErrors();
    plaintext_len = len;
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))                     handleErrors();
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}


// Utility

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

int cardIsValid(CARD_T card){
    return (int) card; // should implement luhn checksum
}

int signatureIsValid(PK_T * pk, SIGN_T * signature){
    return memcmp(pk,signature,8); // chechs a 8 bytes password
}

uint32_t count_tokens(uint8_t *table){
        uint32_t res = 0;
        for(uint32_t i = 0;i<NUM_ROWS;i++){
                if(memcmp(zero_row,table+i*ROW_BYTES,ROW_BYTES))
                        res ++;
    }
        return res;
}


// Print functions

void printb(unsigned char * buf, uint32_t size){
    for(uint32_t i = 0; i < size; i++){
        for(uint32_t j = 0; j < 8; j++)
            printf("%d", (buf[i]>>j) & 1);
    }
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
        uint8_t drow[32];
        decrypt(row, 32, key, iv, drow);

        USES_T usesLeft = drow[12];
        printf("Token %d (%d use", token, usesLeft);
        if(usesLeft > 1) printf("s) of the CB ");
        else  printf(") of CB ");

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
        else seconds = 0;
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
