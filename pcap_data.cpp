#include <pcap.h>
#include <iostream>
#include <cstdlib>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <csignal>
#include <cstring>
#include <cerrno>
#include <ctime>
#include <cctype>
#include <set>
#include <list>
#include <pthread.h>
#include <unistd.h>
#include <semaphore.h>

#include "Mac.h"
#include "pcap_data.h"

using namespace std;


set<Mac> mac_set;
const char *file;

pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
sem_t sem;

Mac *src_mac;
Mac *dst_mac;

struct stats{
    int total_mac;
    int total_pkts;
    int dump_pkts;
} tot_stat = {0};

string mac2String(const u_int8 *mac) {
    char macStr[64];
    sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    return string(macStr);
}

string timeval2String(const struct timeval *tv) {
    struct tm tmv;
    char str[64];
    gmtime_r(&tv->tv_sec, &tmv);
    sprintf(str, "%02d:%02d:%02d.%06d", tmv.tm_hour+8, tmv.tm_min, tmv.tm_sec, tv->tv_usec);
    return string(str);
}

int pkt_mac_handler(const u_int8 *pkt, int mac_no) {
    const int offs[4] = {4,10,16,24};
    //set<int> myset;
    set<Mac>::iterator it;
    pair<set<Mac>::iterator, bool> ret;

    u_int8 type = (pkt[0] & 0x0C) >> 2;
    u_int8 sub_type = (pkt[0] & 0xF0) >> 4;
    u_int8 flags = pkt[1];

    for(int i=0; i<mac_no; i++) {
        //cout << "mac = " << Mac(pkt+offs[i]).toString() << endl;
        tot_stat.total_mac++;
        ret = mac_set.insert(Mac(pkt+offs[i]));
    
        if(ret.second) {
            cout << '[' << mac_set.size() << "] " << ret.first->toString() << endl;
        } else {
            /* exist */
            Mac::rwIterator(ret.first)->counter++;
        }
        
        /* is bssid */
        if(Mac::mac_is_bssid(type, sub_type, flags,i+1)){
            Mac::rwIterator(ret.first)->is_bssid = true;
        }
    }
    
    return 0;
}

string getType(u_int8 type, u_int8 sub_type) {
    switch(type) {
        case 0:
            switch(sub_type) {
                case 0:
                    return "asso req";
                case 1:
                    return "asso response";
                case 2:
                    return "reasso req";
                case 3:
                    return "reasso response";
                case 4:
                    return "probe req";
                case 5:
                    return "probe response";
                case 8:
                    return "beacon";
                case 9:
                    return "ATIM";
                case 10:
                    return "disasso";
                case 11:
                    return "auth";
                case 12:
                    return "deauth";
                default:
                    return "";
            }
        case 1:
            switch(sub_type) {
                case 0xa:
                    return "ps-poll";
                case 0xb:
                    return "rts";
                case 0xc:
                    return "cts";
                case 0xd:
                    return "ack";
                case 0xe:
                    return "cf-end";
                case 0xf:
                    return "cf-end+cf-ack";
                default:
                    return "";
            }
        case 2:
            return "Data";
#if  0
            switch(sub_type) {
                case 0:
                    return "data";
                case 1:
                    return "data+cf-ack";
                case 2:
                    return "data+cf-poll";
                case 3:
                    return "data+cf-ack+cf-poll";
                case 4:
                    return "Null data";
                case 5:
                    return "cf-ack";
                case 6:
                    return "cf-poll";
                case 7:
                    return "data+cf-ack+cf-poll";
                case 8:
                    return "QoS data";
                case 9:
                    return "QoS data+cf-ack";
                default:
                    return "";
            }
#endif
        default:
            return "";
    }
}

//开始读数据包
void process_one_wireless_cap_packet(const char *input, const u_char *pktdata, const struct pcap_pkthdr pkthdr)
{    
    const unsigned char prism_msg_code[] = {0,0,0,0x44};
    const u_char *h80211;
    int channel = 0, rssi = 0, freq = 0;

    if( !memcmp(pktdata, prism_msg_code, 4) ) {
        h80211 = pktdata + ((const unsigned int *)pktdata)[1];
        channel = ntohl(*(long*)(pktdata+0x38));
        rssi = ntohl(*(long*)(pktdata+0x44));
        if(rssi>0) {
            rssi = 0;
        }
    } else {
        h80211 = pktdata+pktdata[2]+(pktdata[3]>>8);
        freq = pktdata[11]*0xff + pktdata[10];
        rssi = *(signed char*)(pktdata+0xe);
    }

    int macNo = 0;
    if(pkthdr.len<12){
        printf("error: pkthdr.len=%d\n",pkthdr.len);
        return;
    }
    else if(pkthdr.len < 18) {
        macNo = 1;
    }
    else if(pkthdr.len < 24) {
        macNo = 2;
    }
    else {
        macNo = 3;
    }

    //hexdump(pktdata, pkthdr.len, "pkt");

    const unsigned short *fc = (const unsigned short *)h80211;
    const u_int8 type = (h80211[0] & 0x0C) >> 2;
    const u_int8 sub_type = (h80211[0] & 0xF0) >> 4;
    const u_int8 flags = h80211[1];

    //cout << src_mac->toString() <<endl;
    if( src_mac && *src_mac != Mac(h80211+10)) {
        return ;
    }
    if( dst_mac && *dst_mac != Mac(h80211+4)) {
        return ;
    }

    //printf("fc = 0x%04x\n", *fc);
    //printf("%02x - %02x\n", type, sub_type);
    if( src_mac && (getType(type, sub_type)=="cts" || getType(type, sub_type)=="ack") ) {
        return;
    }
    cout << timeval2String(&pkthdr.ts) << ' ' 
         << '<' << input << "> "
         << mac2String(h80211+4) << ' '
         << (macNo>1?mac2String(h80211+4+6):"") << ' '
         << (macNo>2?mac2String(h80211+4+12):"") << ' ';
    if( channel ) {
        cout << "CH=" << channel << ' ';
    } 
    else if(freq) {
        cout << "freq=" << freq << ' ';
    }
    cout << "rssi=" << rssi << ' '
         << "type=" << getType(type,sub_type)
         << endl;
    fflush(stdout);
    tot_stat.dump_pkts++;
#if  0
    switch(type) {
        case 0:
            /* 3 mac fields */
            //printf("manage\n");
            pkt_mac_handler(h80211, 3);
        break;
        case 1:
            switch(sub_type) {
                case 0xa:
                case 0xb:
                case 0xe:
                    /* 2 mac fields */
                    //printf("ctrl-(PsPoll/RTS/CF-End)\n");
                    pkt_mac_handler(h80211, 2);
                break;

                case 0xc:
                case 0xd:
                    /* 1 mac field */
                    //printf("ctrl-(CTS/ACK)\n");
                    pkt_mac_handler(h80211, 1);
                break;

                case 0xf:
                    //printf("ctrl-CF-END+CF-ACK\n");
                break;
                default:
                    //printf("ctrl-Unknown\n");
                break;
            }
        break;
        case 2:
            if( 0x3 == (flags & 0x3) ) {
                /* WDS: 4 mac fields */
                //printf("data-WDS\n");
                pkt_mac_handler(h80211, 4);
            } else {
                /* 3 mac fields */
                //printf("data-Data\n");
                pkt_mac_handler(h80211, 3);
            }
        break;
        default:
            //printf("!!!UNKNOWN\n");
        break;
    }
#endif
}

void *record_routine(void *arg) {
    sem_wait(&sem);

    pthread_mutex_lock(&mtx);
    cout << endl;
    int bssid_cnt=0;
    for(set<Mac>::iterator it=mac_set.begin(); it != mac_set.end(); it++) {
        if(it->is_bssid) {
            bssid_cnt++;
        }
    }
    cout << "dump packets = " << tot_stat.dump_pkts << endl;
    cout << "total packets = " << tot_stat.total_pkts << endl;
    if(file) {
        Mac::mac_set_all_file(mac_set, file);
        Mac::mac_set_sort_file(mac_set, file);
        Mac::mac_set_bssid_file(mac_set, file);
    }
    exit(0);
}

void *cap_routine(void *arg) {
    pcap_t *pcap_handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    const u_int8 *pktdata = NULL;
    struct pcap_pkthdr pkthdr;
    const char *input = (char *)arg;

    cout << "input: " << input << endl;
    sleep(2);

    /* open a file or a netdev */
    pcap_handle = pcap_open_live(input, BUFSIZ, 1, 1000*60, errbuf);
    if(!pcap_handle) {
        pcap_handle = pcap_open_offline(input, errbuf);
    }
    
    if(!pcap_handle)
    {
        cout << errbuf << endl;
        return NULL;
    }

    while ( (pktdata = pcap_next(pcap_handle,&pkthdr)) != NULL ){
        tot_stat.total_pkts++;
        process_one_wireless_cap_packet(input, pktdata, pkthdr);
    }
    pcap_close(pcap_handle);
    return NULL;
}

void int_handler(int signo) {
    if( signo == SIGINT ) {
        sem_post(&sem);
    }
}

int main(int argc ,char **argv)
{
    sem_init(&sem, 0, 0);
    signal(SIGINT, int_handler);

    if(argc < 2) {
        printf("usage: %s <dev1> [dev2] [-s src-mac] [-d dst-mac]\n", argv[0]);
        exit(0);
    }
    pthread_t tid;
    pthread_create(&tid, NULL, record_routine, NULL);
    pthread_detach(tid);
    for(int i=1; i<argc; i++) {
        if(string(argv[i]) == "-w") {
            file = argv[++i];
            continue;
        }
        else if ( !strncmp(argv[i], "-w", 2) ) {
            file = argv[i] + 2;
            continue;
        }

        if(string(argv[i]) == "-s") {
            src_mac = new Mac(argv[i+1]);
            i++;
            continue;
        }
        if(string(argv[i]) == "-d") {
            dst_mac = new Mac(argv[i+1]);
            i++;
            continue;
        }

        pthread_t tid;
        pthread_create(&tid, NULL, cap_routine, argv[i]);
        pthread_detach(tid);
    }
    
    char line[1024];
    for(; fgets(line, sizeof line, stdin);) {
        if(!strncmp(line, "quit", 4)) {
            raise(SIGINT);
        }
    }
    return 0;
}

