#include <cstring>
#include <cstdio>
#include "Mac.h"



Mac::Mac(const unsigned char * src) {
    memcpy(mac, src, 6);
    counter = 1;
}


bool Mac::operator< (const Mac & m) const {
    return memcmp(mac, m.mac, 6) < 0 ;
}


string Mac::toString() const {
    char tmp[32];
    sprintf(tmp, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    return string(tmp);
}

int Mac::incCounter() {
    return ++counter;
}