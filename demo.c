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

struct row {
  unsigned long long cb;
  int r;
  unsigned char useNumber;
  unsigned long long t;
  short extra1;
  int extra2;
 };

#define aesSize 256
#define HASH_LENGTH 2*SHA224_DIGEST_LENGTH+1
#define RED   "\x1B[31m"
#define GRN   "\x1B[32m"
#define YEL   "\x1B[33m"
#define BLU   "\x1B[34m"
#define MAG   "\x1B[35m"
#define CYN   "\x1B[36m"
#define WHT   "\x1B[37m"
#define RESET "\x1B[0m"
int size = pow(10,5);
int randsize = (int)pow(2,28);

unsigned long long get_time(struct timeval t){
  unsigned long long sum;
  unsigned long long seconds = t.tv_sec;
  unsigned long long microseconds = t.tv_usec;
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

void tokenization(struct row *table,unsigned long long cb, unsigned char useN, unsigned long long deadline,unsigned int *tokenToReturn,int *insertion){
  unsigned char buffer[4];
  unsigned int *r;
  unsigned char *hash =  malloc(HASH_LENGTH);
  unsigned int token;
  int timepast = 0;
  struct timeval begin, end;
  double sum=0;
  do{
    RAND_bytes(buffer, sizeof(buffer));
    r = (unsigned int*)buffer;
    gettimeofday(&begin,0);
    SHA224((const unsigned char *)r, sizeof(unsigned int), hash);
    token =((*(unsigned int*)hash)) % size;
    gettimeofday(&end,0);
    sum += get_time_execution(begin,end);
  }
  while (table[token].cb != 0 && sum<0.1);
  if (table[token].cb == 0){
    table[token].cb = cb;
    table[token].r = *r;
    table[token].useNumber=useN;
    table[token].t = deadline;
    *tokenToReturn = token;
    *insertion = 1;
  }
  else *insertion = 0; 
  free(hash);
}

void clean(struct row *rowToDelete){
  rowToDelete->cb=0;
  rowToDelete->r=0;
  rowToDelete->useNumber=0;
  rowToDelete->t=0;
  rowToDelete->extra1=0;
  rowToDelete->extra2=0;
}

void clean_table(struct row *table){
    for (int i=0;i<size;i++) clean(table+i);
}


void detokenization(struct row *table, int token,unsigned long long *cbToreturn){
  struct timeval tempTime;
  gettimeofday(&tempTime,0);
  unsigned long long tDays = get_time(tempTime);
  if((table[token].useNumber)>0 && (table[token].t)>tDays){
    *cbToreturn = table[token].cb;
    if (table[token].useNumber>1)
      table[token].useNumber=table[token].useNumber-1;
    else{
      printf("clean: ");
      printf(RED "maximal number of use reached\n" RESET);
      clean(&table[token]);
    }
  }
  else{
    printf("clean: ");
    printf(RED "obsolete\n" RESET);
    clean(&table[token]);
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

void print_CB(unsigned long long CB) {
    unsigned long long CB1 = CB % (unsigned long long) pow(10,4);
    unsigned long long CB2 = (CB / (unsigned long long) pow(10,4)) % (unsigned long long) pow(10,4);
    unsigned long long CB3 = (CB / (unsigned long long) pow(10,8)) % (unsigned long long) pow(10,4);
    unsigned long long CB4 = (CB / (unsigned long long) pow(10,12)) % (unsigned long long) pow(10,4);
    printf(BLU"%lld_%lld_%lld_%lld ***\n" RESET, CB1,CB2,CB3,CB4);
}

void print_row(struct row * table, int token) {
  if(table[token].cb == 0) printf("The token %d is not in the table!\n",token); else{
  printf("-----------------------------------------------------------\n");
  printf("Token %d (%d use", token, table[token].useNumber);
  if(table[token].useNumber > 1){
    printf("s) of the CB ");
  }
  else{
    printf(") of ");
  }
  print_CB(table[token].cb);
  //TIME
  struct timeval t;
  gettimeofday(&t, 0);
  unsigned long long temp = get_time(t);
  unsigned long long seconds;
  if (table[token].t > temp) seconds = (table[token].t - temp);
  else seconds = 0;
  print_expiracy(seconds);
  printf("  (generated with the random %d)\n", table[token].r);
  printf("-----------------------------------------------------------\n\n\n");
 }
}

void print_table(struct row * table, int * ListOfTokens, int beg, int end) {
  int nb = 0;
  for (int j = 0 ; j<size;j++){
    if (table[j].cb != 0) nb++;
  }
  printf("###########################################################\n");
  printf("#################  TABLE OF %d TOKENS  ###############\n", nb);
  printf("###########################################################\n");
  for (int k = beg ; k < end ; k++) {
    if(table[ListOfTokens[k]].cb != 0) print_row(table, ListOfTokens[k]);
  }
}

int main(){
  struct timeval t;
  double mean;
  gettimeofday(&t, 0);
  unsigned long long cb;
  unsigned long long temp = get_time(t) + 10000;
  //creation of the table
  struct row *table = malloc (size * sizeof(struct row));
  for (int i = 0 ; i < size ; i++) {
    table[i].cb=0;
  }
  //insert `size` tokens
  clock_t cleanTime;
  int * FirstTokens = malloc(10 * sizeof(int));
  for (int i = 0;i<size;i++) {
    int token;
    unsigned char nbUse;
    clock_t tempTime, sumToken = 0;
    int inserstion = 1;
    cb = 4837562834756787 + i;
    nbUse = rand()%255+1;
    tempTime = clock();
    tokenization(table,cb,nbUse, temp+nbUse*1000, &token,&inserstion);
    if (i<10) FirstTokens[i] = token;
    sumToken+=clock()-tempTime;
    if(inserstion==0){
      printf("BREAK\n");
      break;
    }
  }

  //for after...
  table[FirstTokens[0]].useNumber = 2;

  
  // print the number of tokens inserted
  unsigned int nbTokenInserted = 0;
  for(int i=0;i<size;i++){
    if(table[i].cb!=0) nbTokenInserted++;
  }
  float perc = nbTokenInserted*100/size;
  printf("%d tokens generated (%.2f%c)\n\n", nbTokenInserted, perc, 37);



  
  char key, kkey;

  do {
    printf("[1] display the first tokens\n");
    printf("[2] display one token\n");
    printf("[3] tokenization\n");
    printf("[4] detokenization\n");
    printf("[5] clean the table\n");
    printf("[x] quit.\n");
    scanf(" %c", &key);

    if(key == '1') {
      print_table(table, FirstTokens, 0, 5);
    }
    if(key == '2') {
      printf("Token: ");
      int tok;
      scanf("%d", &tok); 
      print_row(table, tok);
    }
    if(key == '3') {
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
      tokenization(table,CB,nbUse, temp+t, &token, &insertion);
      if (FirstTokens[0] == 0){
	FirstTokens[0] = token;
      }
      if(insertion == 1) {
	printf("Token added!\n");
	print_row(table, token);
      }
      else printf("No token added.\n");
    }
    if(key == '4') {
      printf("Detokenization\n\n");
      unsigned long long CB1;
      int token;
      printf("Token: ");
      scanf("%d", &token);
      detokenization(table, token, &CB1);
      print_row(table, token);
      if (table[token].cb == 0) {
	FirstTokens[0] = 0;
      }
    }
    if(key == '5') {
      clean_table(table);
      printf("Table cleaned\n");
    }
  } while (key != 'x');
  

/*
  // print the ten first tokens
  print_table(table, FirstTokens, 0, 5);
  
  printf(".\n.  (press a key)\n.\n");
  scanf("%c", &key);

  // detokenization of the first one
  unsigned long long CB1;
  printf("Detokenization 1 of the token %d...\n", FirstTokens[0]);
  detokenization(table, FirstTokens[0], &CB1);
  print_CB(CB1);
  printf("Detokenization is " GRN "OK" RESET "!\n\n");
  printf("Detokenization 2 of the token %d...\n", FirstTokens[0]);
  detokenization(table, FirstTokens[0], &CB1);
  print_CB(CB1);
  printf("Detokenization is " GRN "OK" RESET "!\n\n");
  printf("Detokenization 3 of the token %d...\n", FirstTokens[0]);
  detokenization(table, FirstTokens[0], &CB1);



  printf(".\n.  (press a key)\n.\n");
  scanf("%c", &key);

  gettimeofday(&t, 0);
  temp = get_time(t);
  
  table[FirstTokens[1]].t = temp +1;
  print_row(table, FirstTokens[1]);
  clean(table+FirstTokens[1]);
  printf("CLEAN IS ");
  printf(GRN "OK" RESET);
  printf(":\n");
  print_row(table, FirstTokens[1]);





  
  printf(".\n.  (press a key)\n.\n");
  scanf("%c", &key);
  
  // print the ten first tokens
  print_table(table, FirstTokens, 2, 5);
  //for(int i = 2; i < 7 ; i++) {
  //  print_row(table, FirstTokens[i]);
  //}

*/
  
  free(FirstTokens);
  free(table);
    
}

