#ifndef  __MAC_H
#define  __MAC_H


#include <string>

using namespace std;

class Mac {
private:
public:
    unsigned char mac[6];

    int counter;
    bool is_bssid;

    Mac(const unsigned char *src, bool bssid=false);
    string toString() const ;
    bool operator<(const Mac &m) const ;
    int incCounter();
    static bool mac_count_cmp(const Mac &a, const Mac &b);
    static bool mac_is_bssid(unsigned char type, unsigned char sub_type, unsigned char flags, int mac_no);
};



//bool operator< (const Mac & m1, const Mac &m2);








#endif
