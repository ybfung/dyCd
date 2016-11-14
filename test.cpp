#include <stdio.h>
#include <string.h>
#include <stdlib.h>


static int func2( int a, int b) {
  if( a <= 0 && b <= 0)
    return 0;
  if( a > b)
    return a;
  else
    return b;
}

static int func1( int a, int b) {
  int c =  0;
  if( a > b ) {
    c = a;
  }
  else {
    c = b;
  }

  if( c > 0 ) {
     return c;
  }  
  else {
     return 0;
  }

}

int main(int argc, char **argv) {


   if(argc < 3 ) {
	exit(0);
   }

   int a,b;
   sscanf (argv[1],"%d",&a);
   sscanf (argv[2],"%d",&b);
   
   int result = func1( a, b);
   int result2 = func2( a, b);
   printf("\nResult = %d\n",result);
   printf("\nResult2 = %d\n",result2);
    
   return 0;
}
