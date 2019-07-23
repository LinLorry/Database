#include <string>
#include <list>
#include <vector>

namespace Security
{
    typedef unsigned char byte;
    typedef std::basic_string<unsigned char> byte_string;
    typedef std::list<unsigned char> byte_list;
    typedef std::vector<unsigned char> byte_vector;
    class Security
    {
        typedef unsigned char byte;

        virtual unsigned  long size();

        virtual void seek(int pos);

        virtual bool haveNext();

        virtual bool havePrevious();

        virtual byte* next();

        virtual byte* previous();

        void write(byte* entry);

        void setSize(int size);
    };
}

