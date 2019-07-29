
#ifndef DATABASE_UNTIL_H
#define DATABASE_UNTIL_H

#include <Security/Security.h>

void intToBytes(int i, unsigned char* bytes);

int byteToInt(unsigned char* bytes);

int byteToInt(Security::byte_list::const_iterator & bytes);

#endif