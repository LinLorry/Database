#include <until/byte.h>

void intToBytes(int i, unsigned char* bytes)
{
    *(bytes++) = (unsigned char)(i&0xff);
    *(bytes++) = (unsigned char)((i&0xff00)>>8);
    *(bytes++) = (unsigned char)((i&0xff0000)>>16);
    *(bytes++) = (unsigned char)((i&0xff000000)>>24);
}

int byteToInt(unsigned char* bytes)
{
    int result = *(bytes++);
    result |= (*(bytes++)<<8);
    result |= (*(bytes++)<<16);
    result |= (*(bytes++)<<24);

    return result;
}

int byteToInt(Security::byte_list::const_iterator & bytes)
{
    int result = *(bytes);
    result |= (*(++bytes)<<8);
    result |= (*(++bytes)<<16);
    result |= (*(++bytes)<<24);

    ++bytes;

    return result;
}