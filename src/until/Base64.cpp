#include <until/Base64.h>

Security::byte_string &base64_encode(const Security::byte *data, const size_t length)
{
    if (length > (::std::numeric_limits<Security::byte_string::size_type>::max() / 4u) * 3u)
        throw ::std::length_error("Converting too large a string to base64.");

    // Use = signs so the end is properly padded.
    Security::byte_string *retval = new Security::byte_string((((length + 2) / 3) * 4), '=');
    ::std::size_t outpos = 0;
    int bits_collected = 0;
    unsigned int accumulator = 0;

    for (const Security::byte *i = data; i < data + length; ++i) 
    {
        accumulator = (accumulator << 8) | (*i & 0xffu);
        bits_collected += 8;
        while (bits_collected >= 6) 
        {
            bits_collected -= 6;
            (*retval)[outpos++] = b64_table[(accumulator >> bits_collected) & 0x3fu];
        }
    }

    if (bits_collected > 0) 
    { // Any trailing bits that are missing.
        assert(bits_collected < 6);
        accumulator <<= 6 - bits_collected;
        (*retval)[outpos++] = b64_table[accumulator & 0x3fu];
    }
    assert(outpos >= (retval->size() - 2));
    assert(outpos <= retval->size());
    return *retval;
}


Security::byte_string &base64_decode(const char *data, const size_t length)
{
   int bits_collected = 0;
   unsigned int accumulator = 0;
   Security::byte_string *result = new Security::byte_string;
   
   size_t i = 0;

   for (const char *p = data; p < data+length; ++p)
   {
       char c = *p;
       if (::std::isspace(c) || c == '=')
           continue;

       if ((c > 127) || (c < 0) || (reverse_table[c] > 63))
           throw ::std::invalid_argument("This contains characters not legal in a base64 encoded string.");
            
        accumulator = (accumulator << 6) | reverse_table[c];
        bits_collected += 6;
        if (bits_collected >= 8) 
        {
            bits_collected -= 8;
            *result += static_cast<Security::byte>((accumulator >> bits_collected) & 0xffu);
        }
   }

   return *result;
}