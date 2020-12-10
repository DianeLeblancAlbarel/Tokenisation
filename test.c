
#include "token.h"
#include "tools.h"


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

        temp = get_time(t);

    for (int i = 0;i<10;i++) {
        tempTime = clock();
        try = tokenization(table,(CARD_T) 4837562834756767+i ,(USES_T) 1 ,(TIME_T) temp+1000, pk, token, key, iv);
        if (i<10) FirstTokens[i] = token[0];
        sumToken += clock() - tempTime;
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
                        uint32_t active = count_tokens(table);
            printf("Table cleaned, %d tokens remaining\n",active);
        }
                if(input == '6'){
            unsigned char newkey[32];
            unsigned char newiv[16];
            RAND_bytes(newkey, 32);
            RAND_bytes(newiv,16);
                        updateKey(table,key,iv,newkey,newiv);
                        printf("Key updated\n");

                        memcpy(key, newkey,32);
                        memcpy(iv,newiv,16);
                }
    } while (input != 'x');

    free(FirstTokens);
    free(table);
}
