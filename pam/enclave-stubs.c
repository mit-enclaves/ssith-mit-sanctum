#include <stddef.h>

int __errno_location;

char *malloc(size_t size)
{
  return 0;
}

void free(char *x)
{
}

void __assert_fail()
{
}

char *strcpy(char *dst, const char *src)
{
  int i;
  for (i = 0; src[i] != '\0'; i++)
    dst[i] = src[i];
  return dst;
}
void *memmove(void *dst, const void *src, long int len)
{
  return dst;
}

void abort()
{
}

int randombytes_buf()
{
  return 0;
}
int randombytes_stir()
{
return 0;
}
