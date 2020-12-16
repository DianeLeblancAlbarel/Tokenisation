#include "tools.h"
#include "token.h"

#define DOHASH 1

#if DOHASH

int tokenization(uint8_t *table, CARD_T cb, USES_T uses, TIME_T deadline, PK_T  pk, TOKEN_T *tokenToReturn, unsigned char key[32], unsigned char iv[16]){
    /* Tries to find a space to insert a new token into the table
        Inputs:  the table of tokens, 
                 the card number to tokenize, 
                 the number of uses allowed for the token, 
                 the time of expiry of the token, 
                 the extra data stored for user authentification
                 the address of the token to be filled in case of success
                 the key and iv for encryption of the table
        Outputs: 1 in case of success of the token creation
                 0 in case of failure because the timeframe for creation has been exceeded
    */
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
            SHA224((const unsigned char *)row, ROW_BYTES, hash); // hashing allows to check for the correctness of the table
            memcpy(&random, hash,4);
        } while(random > 0b11111010010101101110101000000000); // ensures the distribution is uniform
        
        token = random % NUM_ROWS;

        gettimeofday(&end,0);
        delta = get_time_execution(begin,end);
    } while ( memcmp (zero_row, table + token*ROW_BYTES, 8) && delta<TIMEFRAME); // repeat tries until the timeframe is exceeded

    if ( !memcmp(zero_row, table+token*ROW_BYTES, 8)){ // a spot in the table has been found, encrypt and insert the token
        encrypt (row, 31, key, iv, table+token*ROW_BYTES);
        *tokenToReturn = token;
        return 1;
    }
    else return 0;
}

void clean(uint8_t * row, uint8_t * table, unsigned char key[32], unsigned char iv[16]){
    /* Chechs the validity of a token and zeroes out the memory if it isn't
        Inputs:  the row of the table, 
                 the table
                 the key and iv for encryption of the table
    */
    struct timeval tdays;
    gettimeofday(&tdays,0);
    TIME_T now = get_time(tdays);
    TIME_T expiry;
    CARD_T card;
    TOKEN_T token;
    RAND_T random;
    uint8_t hash[HASH_LENGTH];

    if(memcmp(zero_row, row, 32)){ // token exists
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

        if ( !memcmp(zero_row, drow+12,1)  || expiry < now || !cardIsValid(card) || (row == table+token*ROW_BYTES) ) // if token not valid
            memset(row, 0, ROW_BYTES); 
    }
}

#else
    /* Indentical functions in outputs but different security and efficiency properties */

int tokenization(uint8_t *table, CARD_T cb, USES_T uses, TIME_T deadline, PK_T  pk, TOKEN_T *tokenToReturn, unsigned char key[32], unsigned char iv[16]){
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
            RAND_bytes((unsigned char *)&random, RANDBYTES);
        } while(random > 0b11111010010101101110101000000000);

                memcpy(row+8, &random, 4);
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

        memcpy(&random, drow+8,4);
        token = random % NUM_ROWS;
        memcpy(&card, drow,8);
        memcpy(&expiry, drow+13, 8);

        if ( !memcmp(zero_row, drow+12,1)  || expiry < now || !cardIsValid(card) ) memset(row, 0, ROW_BYTES);
    }
}

#endif

void detokenization(uint8_t *table, TOKEN_T token, CARD_T * card, SIGN_T signature, unsigned char key[32], unsigned char iv[16] ){
    /* Uses the given token by returning the corresponding card number.
        Inputs:  the table of tokens, 
                 the token to use
                 the address to write the card nuber corresponding to the token 
                 the data required for user authentification
                 the key and iv for encryption of the table
    */
    struct timeval tempTime;
    gettimeofday(&tempTime,0);
    TIME_T now = get_time(tempTime);
    TIME_T expiry;
    uint8_t * row = table+token*ROW_BYTES;

    uint8_t drow[32];
    decrypt(row, 32, key, iv, drow); // get the required row as plaintext

    memcpy(&expiry, drow+13, 8);
    if( memcmp(zero_row, drow+12,1) && expiry > now && signatureIsValid((PK_T *) drow+21, &signature) ) { //token is valid
        memcpy(card, drow, 8);
        if (drow[12] > 1 ){
            drow[12] --;
            printf("This token can be used again");
            encrypt(drow,31,key,iv,row);// insert modified date into the table
        }
        else{
            drow[12] --;
            encrypt(drow,31,key,iv,row);
            printf("Maximal number of uses reached, cleaning token\n");
            clean(row, table, key, iv);// clean the used token from the table
        }
    }
    else{
        printf("Token is invalid or obsolete\n");
        clean(row, table, key, iv);
        exit(1);
    }
}

void cleanTable(uint8_t *table, unsigned char key[32], unsigned char iv[16] ){
    /* Chechs the validity of all tokens and zeroes out the memory if it isn't
        Inputs:  the table
                 the key and iv for encryption of the table
    */
    for (uint64_t i=0; i<NUM_ROWS; i++) clean(table+i*ROW_BYTES, table, key, iv);
}

void updateKey(uint8_t *table, unsigned char oldKey[32], unsigned char oldiv[16], unsigned char newKey[32], unsigned char newiv[16]){
    /* Updates the encryption key and iv of the table
        Inputs:  the table
                 the old key and iv 
                 the new key and iv 
    */
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
