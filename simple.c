
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char digits[10] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};

int main(int argc, char *argv[]) {
  static char **table;
  char *line;
  FILE *out = stderr;
  unsigned crc;
  int i, j, size = 0, loop_size = 1;

  if(argc < 2) size = 20;
  else size = atoi(argv[1]);
  if(argc == 3) loop_size = atoi(argv[2]);
  
  fprintf(out, "Malloc table\n");
  table = malloc(sizeof(char *) * size);

  for(i = 0; i < size; i++) {
    line = malloc(sizeof(char) * 10);
    table[i] = line;
    strncpy(line, "Bonjour", 8);
    line[7] = digits[i % 10];
    line[8] = 0;
  }

  // for(i = 0; i < size; i++) {
  //   fprintf(out,"Line %d, %s\n", i, table[i]);
  // }

  crc = 0;
  for(i = 0; i < loop_size; i++) {
//    for(j = 0; j < size; j++) crc += table[j][0];
    for(j = 0; j < size; j++) 
    { 
      line = table[j];
      crc += 1;
      crc += line[0];
    }
  }
  
  for(i = 0; i < size; i++) {
    line = table[i];
    fprintf(out,"Free line %d, %p in table %p\n", i, line, table);
    free(line);
  }
  
  fprintf(out, "Free table, crc = %d\n", crc);
  free(table);
}

