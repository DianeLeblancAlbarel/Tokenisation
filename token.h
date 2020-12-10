
static const uint8_t zero_row[ROW_BYTES] = { 0 };

int tokenization(uint8_t *table, CARD_T cb, USES_T uses, TIME_T deadline, PK_T  pk, TOKEN_T *tokenToReturn, unsigned char key[32], unsigned char iv[16]);
//returns 1 in case of success, 0 otherwise

void detokenization(uint8_t *table, TOKEN_T token, CARD_T * card, SIGN_T signature, unsigned char key[32], unsigned char iv[16] );

void clean(uint8_t * row, uint8_t * table, unsigned char key[32], unsigned char iv[16]);

void cleanTable(uint8_t *table, unsigned char key[32], unsigned char iv[16] );

void updateKey(uint8_t *table, unsigned char oldKey[32], unsigned char oldiv[16], unsigned char newKey[32], unsigned char newiv[16]);
