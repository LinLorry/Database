#include <cstring>
#include <list>
#include <vector>

#include <Security/DatabaseSecurityHeader.h>
#include <until/byte.h>

namespace Security
{
    DatabaseSecurityHeader::DatabaseSecurityHeader(const byte_string &headerBytes, 
                                const byte_string &passwordMd5)
    {
        size_t index = byteToInt((byte*)headerBytes.c_str());

        byte_list list((byte *)headerBytes.c_str() + 4, ((byte *)headerBytes.c_str()) + headerBytes.length());
        byte_list::const_iterator iterator = next(list.cbegin(), index);

        for (size_t i = passwordMd5.length() - 1; i > 0 ; --i)
        {
            if (*iterator!=passwordMd5[i])
            {

            }

            list.erase(iterator);
            --i;

            for (size_t j = 0; (passwordMd5[i] & 0xff) && i!=1;++j)
                if (iterator!=list.cbegin())
                    --iterator;
                else
                    iterator = list.cend();
        }

        iterator = list.cbegin();
        size_t private_key_length = byteToInt(iterator);
        size_t public_key_length = byteToInt(iterator);

        byte_string private_key_string();

        byte_list::const_iterator tmp_iter = iterator;
        next(iterator, private_key_length);

        byte_vector private_key_vector(tmp_iter, iterator);
        private_key_vector.push_back('\0');
        setPrivateKey(private_key_vector.data());

        tmp_iter = ++iterator;
        next(iterator, public_key_length);

        byte_vector public_key_vector(tmp_iter, iterator);
        public_key_vector.push_back('\0');
        setPublicKey(public_key_vector.data());
    }

    const byte_string & DatabaseSecurityHeader::updatePassword(const byte_string &password)
    {
        byte_string *s = new byte_string();
        return *s;
    }


    BIO *DatabaseSecurityHeader::getPublicKey()
    {
        return public_key;
    }

    BIO *DatabaseSecurityHeader::getPrivateKey()
    {
        return private_key;
    }

    void DatabaseSecurityHeader::setPublicKey(const byte *public_key_bytes)
    {
        public_key = BIO_new_mem_buf(public_key_bytes, -1);  
    }

    void DatabaseSecurityHeader::setPrivateKey(const byte *private_key_bytes)
    {
        private_key = BIO_new_mem_buf(private_key_bytes, -1);
    }

    DatabaseSecurityHeader::~DatabaseSecurityHeader()
    {
        BIO_free_all(public_key);
        BIO_free_all(private_key);
    }
}

