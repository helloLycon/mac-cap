#include <cstring>
#include <cstdio>
#include "Mac.h"


Mac::Mac(const unsigned char * src, bool bssid): 
    counter(1), is_bssid(bssid)
{
    memcpy(mac, src, 6);
}


bool Mac::operator< (const Mac & m) const {
    return memcmp(mac, m.mac, 6) < 0 ;
}


string Mac::toString() const {
    char tmp[32];
    sprintf(tmp, "%02x:%02x:%02x:%02x:%02x:%02x (%d%s)", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5],counter, is_bssid?", bssid":"" );
    return string(tmp);
}

Mac * Mac::rwIterator(set<Mac>::iterator &it) {
    return (Mac *)&(*it);
}

bool Mac::mac_count_cmp(const Mac &a, const Mac &b) {
    if (a.counter == b.counter) {
        return memcmp(a.mac, b.mac, 6) < 0;
    }
    return a.counter < b.counter;
}


bool Mac::mac_is_bssid(unsigned char type, unsigned char sub_type, unsigned char flags, int mac_no) {
    unsigned char fromDs = flags & 0x2;
    unsigned char toDs = flags & 0x1;
    switch(type) {
        case 2:
        /* Data */
            if( !fromDs && !toDs && 3==mac_no)
                return true;
            if( !fromDs && toDs && 1==mac_no)
                return true;
            if( fromDs && !toDs && 2==mac_no)
                return true;
            return false;

        case 0:
        /* Manage */
            if( 3==mac_no )
                return true;
            return false;

        case 1:
        /* Control */
            if( 0xa==sub_type && 1==mac_no ) 
                return true;
            return false;
        default:
            return false;
    }
    return false;
}

