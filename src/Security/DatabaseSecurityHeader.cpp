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

    byte_string & DatabaseSecurityHeader::generateHeader(const byte_string &password)
    {
        RSA *keypair = RSA_generate_key(4096, RSA_F4, nullptr, nullptr);

        BIO *pri = BIO_new(BIO_s_mem());
        BIO *pub = BIO_new(BIO_s_mem());

        PEM_write_bio_RSAPrivateKey(pri, keypair, nullptr, nullptr, 0, nullptr, nullptr);  
        PEM_write_bio_RSAPublicKey(pub, keypair);

        byte_string key_string = generateKeyString(pri, pub);

        return confusionByteString(key_string, password);
    }

    byte_string &DatabaseSecurityHeader::generateKeyString(BIO *pri_key, BIO* pub_key)
    {
        size_t pri_key_len = BIO_pending(pri_key);
        size_t pub_key_len = BIO_pending(pri_key);

        byte key_bytes[8 + pri_key_len + pub_key_len + 1];

        byte *p = key_bytes;

        intToBytes(pri_key_len, p);
        p += 4;
        intToBytes(pub_key_len, p);
        p += 4;

        BIO_read(pri_key, p, pri_key_len); 
        p += pri_key_len;
        BIO_read(pub_key, p, pub_key_len);

        key_bytes[8 + pri_key_len + pub_key_len] = '\0';

        return *(new byte_string(key_bytes));
    }

    byte_string &DatabaseSecurityHeader::confusionByteString(const byte_string &b_str, const byte_string &confusion)
    {
        byte_list list((byte *)b_str.c_str(), (byte *)b_str.c_str()+b_str.length());

        byte_list::const_iterator c_iter = list.cbegin();
        size_t index = 0;

        const byte *confusion_byte = confusion.c_str();

        for (size_t i = 0; i < confusion.length(); ++i)
        {
            for (size_t j = 0; j < confusion_byte[i]; ++j)
            {
                if (c_iter != list.cend())
                {
                    ++c_iter;
                    ++index;
                }
                else
                {
                    c_iter = list.cbegin();
                    index = 0;
                }
            }
            list.insert(c_iter, confusion_byte[++i]);
        }

        byte index_bytes[5];
        intToBytes(index, index_bytes);
        index_bytes[4] = '\0';

        byte_string *str = new byte_string(index_bytes);

        for (byte b : list)
            str->push_back(b);

        return *str;
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

