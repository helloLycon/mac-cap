#ifndef  __MAC_H
#define  __MAC_H


#include <string>
#include <set>

using namespace std;

class Mac {
private:
public:
    unsigned char mac[6];

    int counter;
    bool is_bssid;

    Mac(const unsigned char *src, bool bssid=false);
    Mac(const char *str);
    string toString() const ;
    bool operator<(const Mac &m) const ;
    bool operator==(const Mac &m) const ;
    bool operator!=(const Mac &m) const ;
    static Mac * rwIterator(set<Mac>::iterator &it);
    static bool mac_count_cmp(const Mac &a, const Mac &b);
    static bool mac_is_bssid(unsigned char type, unsigned char sub_type, unsigned char flags, int mac_no);
    static int  mac_set_all_file(const set<Mac> &mac_set, const char *file);
    static int  mac_set_sort_file(const set<Mac> &mac_set, const char *file);
    static int  mac_set_bssid_file(const set<Mac> &mac_set, const char *file);
};



#endif
