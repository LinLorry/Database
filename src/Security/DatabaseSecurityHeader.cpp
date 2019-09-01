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

    const byte_string & DatabaseSecurityHeader::generateHeader(const byte_string &password)
    {
        // RSA *keypair = RSA_generate_key(4096, RSA_F4, nullptr, nullptr);
        RSA *keypair = RSA_new();
        int ret = 0;
        BIGNUM *bne = BN_new();
        ret = BN_set_word(bne, RSA_F4);
        ret = RSA_generate_key_ex(keypair, 4096, bne, nullptr);

        // TODO 修改返回实现报错
        if (ret != 1)
            std::abort();

        byte_string key_string = generateKeyString(keypair);

        return confusionByteString(key_string, password);
    }

    const byte_string &DatabaseSecurityHeader::generateKeyString(RSA *keypair)
    {
        BIO *pri_BIO = BIO_new(BIO_s_mem());
        BIO *pub_BIO = BIO_new(BIO_s_mem());
        BIO *pri_BIO_64 = BIO_new(BIO_f_base64());
        BIO *pub_BIO_64 = BIO_new(BIO_f_base64());

        PEM_write_bio_RSAPrivateKey(pri_BIO, keypair, nullptr, nullptr, 0, nullptr, nullptr);
        PEM_write_bio_RSAPublicKey(pub_BIO, keypair);
        
        pri_BIO_64 = BIO_push(pri_BIO_64, pri_BIO);
        pub_BIO_64 = BIO_push(pub_BIO_64, pub_BIO);

        size_t pri_key_len = BIO_pending(pri_BIO_64);
        size_t pub_key_len = BIO_pending(pub_BIO_64);

        byte key_bytes[8 + pri_key_len + pub_key_len];

        unsigned char pri_byte_array[pri_key_len];
        unsigned char pub_byte_array[pub_key_len];

        byte *p = key_bytes;

        intToBytes(pri_key_len, p);
        p += 4;
        intToBytes(pub_key_len, p);
        p += 4;

        BIO_read(pri_BIO_64, p, pri_key_len);
        p += pri_key_len;
        BIO_read(pub_BIO_64, p, pub_key_len);
        p += pub_key_len;

        BIO_free_all(pri_BIO);
        BIO_free_all(pub_BIO);

        return *(new byte_string(key_bytes, 8 + pri_key_len + pub_key_len));        
    }

    const byte_string &DatabaseSecurityHeader::confusionByteString(const byte_string &b_str, const byte_string &confusion)
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

