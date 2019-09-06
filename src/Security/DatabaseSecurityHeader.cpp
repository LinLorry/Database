#include <cstring>
#include <list>
#include <vector>

#include <Security/DatabaseSecurityHeader.h>
#include <until/byte.h>
#include <until/Base64.h>

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
                std::abort();

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
        byte_string private_key_string = DatabaseSecurityHeader::getPrivateKeyString(keypair);
        byte_string public_key_string = DatabaseSecurityHeader::getPublicKeyString(keypair);

        byte prefix[8];
        intToBytes(private_key_string.length(), prefix);
        intToBytes(public_key_string.length(), prefix + 4);

        byte_string *result = new byte_string(prefix, 8);
        result->append(private_key_string);
        result->append(public_key_string);

        return *result;
    }

    const byte_string &DatabaseSecurityHeader::getPrivateKeyString(RSA *keypair)
    {
        BIO *pri_BIO = BIO_new(BIO_s_mem());
        EVP_PKEY *prikey = EVP_PKEY_new();

        PEM_write_bio_RSAPrivateKey(pri_BIO, keypair, nullptr, nullptr, 0, nullptr, nullptr);
        PEM_read_bio_PrivateKey(pri_BIO, &prikey, nullptr, nullptr);
        BIO_free_all(pri_BIO);
        pri_BIO = BIO_new(BIO_s_mem());
        PEM_write_bio_PrivateKey(pri_BIO, prikey, nullptr, nullptr, 0, nullptr, nullptr);
        EVP_PKEY_free(prikey);

        size_t test_len =BIO_pending(pri_BIO);
        char test_str[test_len];
        BIO_read(pri_BIO, test_str, test_len);

        return base64_decode(test_str + 28, test_len - 54);
    }

    const byte_string &DatabaseSecurityHeader::getPublicKeyString(RSA *keypair)
    {
        size_t pub_len = i2d_RSA_PUBKEY(keypair, nullptr);
        unsigned char pub_str[pub_len];
        unsigned char *pub_p = pub_str;
        i2d_RSA_PUBKEY(keypair, &pub_p);
        return *(new byte_string(pub_str, pub_len));
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

