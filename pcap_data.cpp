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
#include <semaphore.h>

#include "Mac.h"
#include "pcap_data.h"

using namespace std;


set<Mac> mac_set;
const char *file;

pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
sem_t sem;

struct stats{
    int total_mac;
    int total_pkts;
} tot_stat = {0};


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

//开始读数据包
void process_one_wireless_cap_packet(const u_char *pktdata, const struct pcap_pkthdr pkthdr)
{    
    const unsigned char prism_msg_code[] = {0,0,0,0x44};
    const u_char *h80211;

    if( !memcmp(pktdata, prism_msg_code, 4) ) {
        h80211 = pktdata + ((const unsigned int *)pktdata)[1];
    } else {
        h80211 = pktdata+pktdata[2]+(pktdata[3]>>8);
    }

    if(pkthdr.len<24){
        printf("error: pkthdr.len=%d\n",pkthdr.len);
        return;
    }

    //hexdump(pktdata, pkthdr.len, "pkt");

    const unsigned short *fc = (const unsigned short *)h80211;
    const u_int8 type = (h80211[0] & 0x0C) >> 2;
    const u_int8 sub_type = (h80211[0] & 0xF0) >> 4;
    const u_int8 flags = h80211[1];
    //printf("fc = 0x%04x\n", *fc);
    //printf("%02x - %02x\n", type, sub_type);
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
    cout << "total bssid = " << bssid_cnt << endl;
    cout << "total mac = " << mac_set.size() << endl;
    cout << "total mac(duplicated) = " << tot_stat.total_mac << endl;
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
    const char *dev = (char *)arg;

    cout << "dev: " << dev << endl;
    pcap_handle = pcap_open_live(dev, BUFSIZ, 1, 1000*60, errbuf);
    if(!pcap_handle)
    {
        cout << errbuf << endl;
        return NULL;
    }

    sleep(2);
    while ( (pktdata = pcap_next(pcap_handle,&pkthdr)) != NULL ){
        //g_packetnum++;
        //printf("%d\n", g_packetnum);
        pthread_mutex_lock(&mtx);
        tot_stat.total_pkts++;
        process_one_wireless_cap_packet(pktdata, pkthdr);
        pthread_mutex_unlock(&mtx);
    }
    cout << "timed out" << endl;
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
        printf("usage: %s <dev> [-w file]\n", argv[0]);
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

        pthread_t tid;
        pthread_create(&tid, NULL, cap_routine, argv[i]);
        pthread_detach(tid);
    }
    
    char line[1024];
    for(; fgets(line, sizeof line, stdin);) {
        if(!strncmp(line, "exit", 4)) {
            raise(SIGINT);
        }
    }
    return 0;
}

