#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>

int
main (int argc, char **argv)
{
    int arr[4];
  if(argc ==5)
  {
    for(int i=1;i < argc; i++)
    {
        arr[i-1] = atoi(argv[i]);
        //printf("arr[%d]: %d\n", i-1, arr[i-1]);
    }
    printf("%d %d\n", fibonacci(arr[0]), max_of_four_int(arr[0], arr[1], arr[2], arr[3]));
    return EXIT_SUCCESS;
  }
  else
    return EXIT_FAILURE;
}
