#ifndef  __MAC_H
#define  __MAC_H


#include <string>

using namespace std;

class Mac {
private:
public:
    unsigned char mac[6];

    int counter;

    Mac(const unsigned char *src);
    string toString() const ;
    bool operator<(const Mac &m) const ;
    int incCounter();
};



//bool operator< (const Mac & m1, const Mac &m2);








#endif
