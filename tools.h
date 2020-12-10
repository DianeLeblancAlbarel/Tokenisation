#ifndef TOOLS
#define TOOLS

void handleErrors(void);

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,unsigned char *iv, unsigned char *ciphertext);

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);

TIME_T get_time(struct timeval t);

double get_time_execution(struct timeval begin, struct timeval end);

int cardIsValid(CARD_T card);

int signatureIsValid(PK_T * pk, SIGN_T * signature);

uint32_t count_tokens(uint8_t *table);

void printb(unsigned char * buf, uint32_t size);

void print_expiracy(unsigned long long seconds);

void print_CB(CARD_T CB);

void print_row(uint8_t * table, TOKEN_T token, unsigned char key[32], unsigned char iv[16]);

void print_table(uint8_t * table, TOKEN_T * ListOfTokens, int beg, int end, unsigned char key[32], unsigned char iv[16]);

#endif
