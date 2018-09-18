#ifndef  __MAC_H
#define  __MAC_H


#include <string>

using namespace std;

class Mac {
public:
    unsigned char mac[6];

    Mac(const unsigned char *src);
    string toString() const ;
    bool operator<(const Mac &m) const ;
};



//bool operator< (const Mac & m1, const Mac &m2);








#endif
