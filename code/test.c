#include "token.h"
#include "tools.h"


struct timeval begin,end,t;
time_t tt;
clock_t firstToken=0, lastToken=0, sumToken=0, tempTime, cleanTime, temp;
double first, last, mean;
CARD_T cb;
PK_T pk = 1234;
SIGN_T sign = 1234;
unsigned char key[32];
unsigned char iv[16];
unsigned long long size = (unsigned long )NUM_ROWS * (unsigned long long)ROW_BYTES;


/*
@param/return table that have to be fill
@param/return trialsPerTimeFrame array of trials numbers for each token of the table
@param/return lastRow the last row generate without exceeding the time frame
@param/return fillinGRate rate of feeling before the first failure
@param/return cardNumber card number that will be generate in the table
@param/return tokenGenerate token that will be generate
@param/return timeToGenerate total time in seconds to generate the table
*/
 void generationTable (uint8_t *table, int *trialsPerTimeFrame,int *lastRow,double *fillingRate,CARD_T * cardNumber, TOKEN_T *tokenGenerate, double *timeTogenerate){
    TOKEN_T token[1];
    int success=1;
    int numberTry = 0;
    int rowNumber = 0;
    struct timeval begin,end,t;
    while (success==1 && rowNumber<NUM_ROWS ){
        gettimeofday(&begin,0);
        gettimeofday(&t,0);
        temp = get_time(t);
       success = tokenization(table,(CARD_T) 4837562834756767+rowNumber ,(USES_T) 2 ,(TIME_T) temp+100000, pk, token, key, iv,&numberTry);      
       gettimeofday(&end,0);
       *timeTogenerate+=get_time_execution(begin,end);      
        *(trialsPerTimeFrame+rowNumber)=numberTry;
        *(cardNumber+rowNumber)= 4837562834756767+rowNumber;
        *(tokenGenerate+rowNumber)=*token;
        rowNumber+=1;
        numberTry=0;
    }
    if (rowNumber==NUM_ROWS){
        *lastRow=rowNumber-1;
    }
    else
        *lastRow=rowNumber-2;
    *fillingRate=((double)*lastRow/(NUM_ROWS-1))*100;
}


/*
@param generateToken array of previous generate tokens that have to correspond to which in table
@param cardNumber array of previous used card number that have to correspond to which in table
@param lastRow number of row
@param/return timeToDetokenise total time used to detokenise one time all the row of the table
@param/return table of previous generate table which will be update
*/
void detokenizationTest (uint8_t *table,TOKEN_T *generateToken, CARD_T *cardNumber,int lastRow,double *timeToDetokenise){
    struct timeval begin,end;
    gettimeofday(&begin,0);
    for (int i =0;i<lastRow-1;i++)
        detokenization(table,*(generateToken+i),(cardNumber+i),sign,key,iv);
    gettimeofday(&end,0);
    *timeToDetokenise=get_time_execution(begin,end);
}

/*
@param/return table table that have to be update
@param/return timeToUpdate total time to update all the table
@param newKey chosen new key
@param newIv chosen new iv
*/
void updateKeyTest (uint8_t *table, double *timeToUpdateKey,unsigned char *newKey,unsigned char *newIV){
    struct timeval begin,end;
    gettimeofday(&begin,0);
    updateKey(table,key,iv,newKey,newIV);
    gettimeofday(&end,0);
    *timeToUpdateKey=get_time_execution(begin,end);
}

/*
@param/return table table that have to be clean
@param/return timeToclean Total time need to clean the table
*/
void cleanTest (uint8_t * table, double *timeToclean){
    struct timeval begin,end;
    gettimeofday(&begin,0);
    cleanTable(table,key,iv);
    gettimeofday(&end,0);
    *timeToclean=get_time_execution(begin,end);
}

int main(){
  
FILE * fp;
fp = fopen("testTokenisation.txt","a+");
// Number of test wanted 
int numberTest = 10;
for (int i = 0;i<numberTest;i++){
    RAND_bytes(key, 32);
    RAND_bytes(iv,16);
    unsigned char newKey[32];
    unsigned char newIv[16];
    RAND_bytes(newKey, 32);
    RAND_bytes(newIv,16);
    uint8_t * table=calloc(size,sizeof(uint8_t));
    int lastRow=0,min = 2147483647u,max = 0;
    double filling = 0,timeToGenerate=0,timeToDetokenize=0,timeToClean=0,timeToUpdate=0;
    int *trialsPerTimeFrame = calloc(NUM_ROWS,sizeof(int));
    CARD_T *cardNumber = calloc(NUM_ROWS,sizeof(CARD_T));
    TOKEN_T *generateToken = calloc(NUM_ROWS,sizeof(TOKEN_T));

    generationTable(table,trialsPerTimeFrame,&lastRow,&filling,cardNumber,generateToken,&timeToGenerate);
    minmaxValue(trialsPerTimeFrame,lastRow,&min,&max);
    detokenizationTest(table,generateToken,cardNumber,lastRow,&timeToDetokenize);
    cleanTest(table,&timeToClean);
    fprintf(fp,"table filling rate for %d rows : %f%%\n",NUM_ROWS,filling);
    if(filling<100)
        fprintf(fp,"try at the first failure : %d\n",*(trialsPerTimeFrame+lastRow+1));
    fprintf(fp,"try at the last row : %d\nmaximum try %d\nminimum try %d\n",*(trialsPerTimeFrame+lastRow),max,min);
    fprintf(fp,"time to generate a table : %f secondes\n",timeToGenerate);
    fprintf(fp,"time to detokenize all the row : %f, per row : %f\n",timeToDetokenize,timeToDetokenize/lastRow);
    fprintf(fp,"time to update key : %f\n",timeToUpdate);
    fprintf(fp,"time to clean the table : %f\n",timeToClean);
    fprintf(fp,"########\n");
    free(table);
    free(trialsPerTimeFrame);
    free(cardNumber);
    free(generateToken);
}
fclose(fp);

}

