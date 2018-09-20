#include <pcap.h>
#include <iostream>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <csignal>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <set>
#include <list>

#include "pcap_data.h"
#include "Mac.h"

using namespace std;

set<Mac> mac_set;

bool b_cap = true;

const char *file;


struct stats{
    int total_mac;
    int total_pkts;
} tot_stat;


void hexdump(const void *ptr, int len, const char *tip) {
    int i;
    if(tip) {
        printf("%s: ", tip);
    }
    for(i=0; i<len ;i++) {
        printf("%02x ", *((const unsigned char *)ptr + i));
    }
    printf("\n");
}

template<class T>
inline T & GetStdSetElement(std::_Rb_tree_const_iterator<T>  std_set_iterator) {
    return *(T *)&(*std_set_iterator);
}


int pkt_mac_handler(const u_int8 *pkt, int mac_no) {
    const int offs[4] = {4,10,16,24};
    //set<int> myset;
    set<Mac>::iterator it;
    pair<set<Mac>::iterator, bool> ret;

    if(b_cap == false ) {
        for(;;) {
            sleep(10);
        }
    }

    for(int i=0; i<mac_no; i++) {
        //cout << "mac = " << Mac(pkt+offs[i]).toString() << endl;
        tot_stat.total_mac++;
        ret = mac_set.insert(Mac(pkt+offs[i]));
        if(ret.second) {
            //cout << "begin = " << mac_set.begin()->toString() << endl;
            //cout << "end   = " << mac_set.end()->toString() << endl;
            cout << '[' << mac_set.size() << "] " << ret.first->toString() << endl;
        } else {
            /* exist */
            GetStdSetElement(ret.first).incCounter();
        }
    }
    
    return 0;
}

//��ʼ�����ݰ�
void process_one_wireless_cap_packet(const u_char *pktdata, const struct pcap_pkthdr pkthdr)
{    
    const unsigned char prism_msg_code[] = {0,0,0,0x44};
    IEEE_802_11_info *pt_iee_802_11_info = NULL;
    Logical_Link_Ctl *pt_logical_linkctl = NULL;
    IPHeader_t *pt_ip_header = NULL;
    TCPHeader_t *pt_tcp_header = NULL;
    char src_ip[STRSIZE], dst_ip[STRSIZE];
    char src_mac[STRSIZE], dst_mac[STRSIZE];
    u_int32 src_port, dst_port;
    unsigned char *pmac = NULL;
    u_int8 iphead_len, tcphead_len;
    u_int16 iptotal_len;
    char my_time[STRSIZE];
    static struct timeval current_time;
    const u_char *pktdata_temp = pktdata;
    phone_data data_record;


    unsigned long i;
    unsigned dbm_offset;
    char dbm;


    
    const u_char *h80211;
    if( !memcmp(pktdata, prism_msg_code, 4) ) {
        h80211 = pktdata + ((const unsigned int *)pktdata)[1];
    } else {
        h80211 = pktdata+pktdata[2]+(pktdata[3]>>8);
    }
    //u_char bssid[6]={0,0,0,0,0,0};
    //u_char bssid_flag=0;
    //u_char stmac[6]={0,0,0,0,0,0};
    //u_char stmac_flag=0;
   /* memset(&data_record, 0, sizeof(data_record));
    memset(&current_time, 0, sizeof(current_time));*/
   // printf("h80211[0]=0\n",h80211[0]);
    //printf("len = %d\n", pkthdr.len);
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


bool mac_count_cmp(const Mac &a, const Mac &b) {
    if (a.counter == b.counter) {
        return memcmp(a.mac, b.mac, 6) < 0;
    }
    return a.counter < b.counter;
}

int mac_set_sort(void) {
    list<Mac> mac_list;
    for( set<Mac>::iterator it = mac_set.begin(); it!=mac_set.end(); it++ ) {
        mac_list.push_back(*it);
    }
    mac_list.sort(mac_count_cmp);

    string sort_file = string(file) + ".sort";
    cout << "write into file: " << sort_file << endl;
    FILE *fp = fopen( sort_file.c_str(), "w" );
    if(!fp) {
        //cout << "write into " << sort_file << " failed" << endl;
        perror("fopen");
        return -1;
    }
    
    for( list<Mac>::iterator it=mac_list.begin(); it!=mac_list.end(); it++ ) {
        fprintf(fp, "%s (%d)\n", it->toString().c_str(), it->counter);
    }
    fclose(fp);
    return 0;
}


void int_handler(int signo) {
    if( signo == SIGINT ) {
        b_cap = false;
        cout << endl;
        cout << "total mac = " << mac_set.size() << endl;
        cout << "total mac(duplicated) = " << tot_stat.total_mac << endl;
        cout << "total packets = " << tot_stat.total_pkts << endl;
        if(file) {
            cout << "write into file: " << file << endl;
        
            FILE *fp = fopen(file, "w");
            if(!fp) {
                perror("fopen");
            }
            for( set<Mac>::iterator it = mac_set.begin(); it!=mac_set.end(); it++ ) {
                fprintf(fp, "%s (%d)\n", it->toString().c_str(), it->counter);
            }
            fprintf(fp, "total mac = %d\n", mac_set.size());
            fprintf(fp, "total mac(duplicated) = %d\n", tot_stat.total_mac);
            fprintf(fp, "total packets = %d\n", tot_stat.total_pkts);
            fclose(fp);
            mac_set_sort();
        }
        exit(0);
    }
}

int main(int argc ,char **argv)
{
    pcap_t *pcap_handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    const char *net_interface = "wlan0";
    struct bpf_program bpf_filter = {0};
    char bpf_filter_string[] = "";//tcp";
    bpf_u_int32 net_mask = 0;
    bpf_u_int32 net_ip = 0;
    int ret = 0;
    int len = 0;
    const u_int8 *pktdata = NULL;
    struct pcap_pkthdr pkthdr;
    unsigned long i,j;

    //test();

    tot_stat.total_mac = tot_stat.total_pkts = 0;
    signal(SIGINT, int_handler);

    if(argc < 2) {
        printf("usage: %s <dev> [w-file]\n", argv[0]);
        exit(0);
    }
    if(argc >= 3) {
        file = argv[2];
    }
    
    const char *dev = argv[1];
    printf("dev = %s\n", dev);
    pcap_handle = pcap_open_live(dev, BUFSIZ, 1, 1000*60, errbuf);

    if(!pcap_handle)
    {
        fprintf(stderr, "pcap_open_live: %s\n",errbuf);
        exit(1);
    }
    while ( (pktdata = pcap_next(pcap_handle,&pkthdr)) != NULL ){
        //g_packetnum++;
        //printf("%d\n", g_packetnum);
        tot_stat.total_pkts++;
        process_one_wireless_cap_packet(pktdata, pkthdr);
    }
    cout << "timed out" << endl;
    pcap_close(pcap_handle);

    exit(EXIT_SUCCESS);
    return 0;
}

