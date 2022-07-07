#include <stdio.h>
#include <stdlib.h>

int main()
{
  int i;
  int j;
  int k;
  int v4[4];
  char enc[] = "_ct7_tHey_1nN0_p";
  for ( i = 0; i <= 3; ++i )
  {
    for ( j = 0; j <= 3; ++j )
      *(&v4[i] + j) = enc[4 * j + i];
  }
  printf(&v4);
  return 1234;
}


// _ct7_tHey_1nN0_p
// //__yN
// //ct_0
// //tH1_
// //7enp
