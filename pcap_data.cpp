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

//开始读数据包
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
/*    
    if( ( h80211[0] & 0x0C ) == 0x04 ){
       // printf("h80211[0]=%x\n",h80211[0]);
        return;
    }
    if ( pkthdr.len > 28)
    {
        if ( memcmp(h80211 + 24, llcnull, 4) == 0)
        {
          //  printf("h80211[24]=0\n");
            return;
        }
    }
*/
#if  0
    //81142
    dbm_offset=((pktdata[4]&0x1)*8)+((pktdata[4]>>1)&0x1)+1+((pktdata[4]>>3)&0x1)*4+((pktdata[4]>>4)&0x1)*2;
    //pt_iee_802_11_info =  (IEEE_802_11_info *)pktdata;
    dbm=(char)pktdata[dbm_offset+8];

    switch( h80211[1] & 3 )
        {
            case  0:
                memcpy(bssid, (h80211 + 16), 6);
                break;  //Adhoc

            case  1:
                memcpy(bssid, (h80211 +  4), 6);
                break;  //ToDS

            case  2:
                memcpy(bssid, (h80211 + 10), 6);
                break;  //FromDS

            case  3:
                memcpy(bssid, (h80211 + 10), 6);
                break;  //WDS -> Transmitter taken as BSSID

            default :
                break;
        }

    for(i=0;i<ap_count;i++){
        if(ap[i].bssid[0]==bssid[0] && ap[i].bssid[1]==bssid[1] && ap[i].bssid[2]==bssid[2] && ap[i].bssid[3]==bssid[3]&&  ap[i].bssid[4]==bssid[4] \
           &&  ap[i].bssid[5]==bssid[5] ){ap[i].count++;break;}
        if(bssid[0]==0 && bssid[1]==0 && bssid[2]==0 )break;
        if(bssid[0]&0x1)break;
    }
    if(i==ap_count){
        memcpy(ap[ap_count++].bssid,bssid,6);
        ap[i].count=1;
         ap[i].pk_number=g_packetnum;
         ap[i].dbm=dbm;
        printf("bssid_mac=%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\tdbm=%d\tap_count=%d\tg_packetnum=%d\n",bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5],dbm,ap_count,g_packetnum);
    }

    switch( h80211[1] & 3 )
        {
            case  0:
                    /* if management, check that SA != BSSID */
        if( memcmp( h80211 + 10, bssid, 6 ) != 0 ) {memcpy( stmac, h80211 + 10, 6 );stmac_flag=1;}
                    break;

            case  1:
                    /* ToDS packet, must come from a client */
                    if( memcmp( h80211 + 10, bssid, 6 ) != 0 )   {memcpy( stmac, h80211 + 10, 6 );stmac_flag=1;}
                break;

            case  2:

                /* FromDS packet, reject broadcast MACs */

                if( (h80211[4]%2) == 0) {
                    if(memcmp( h80211 + 10, bssid, 6 ) != 0 ){
                        memcpy( stmac, h80211 +  4, 6 );
                        stmac_flag=1;
                    }
                }
                break;
            default:
                break;
        }

    /*switch( h80211[1] & 3 ){
        case  0:pmac = &pktdata[10+pktdata[2]+(pktdata[3]>>8)];break;
        case  1:pmac = &pktdata[10+pktdata[2]+(pktdata[3]>>8)];break;
        case  2:
            pmac = &pktdata[10+pktdata[2]+(pktdata[3]>>8)];
            break;
        case  3:
    }*/

    if(stmac_flag){
        for(i=0;i<mac_count;i++){
            if(sta[i].mac[0]==stmac[0] && sta[i].mac[1]==stmac[1] && sta[i].mac[2]==stmac[2] && sta[i].mac[3]==stmac[3]&&  sta[i].mac[4]==stmac[4] \
               &&  sta[i].mac[5]==stmac[5] ){sta[i].count++; break;}
            if(stmac[0]==0 && stmac[1]==0 && stmac[2]==0 )break;
        }
        if(i==mac_count){
            memcpy(sta[mac_count++].mac,stmac,6);
            sta[i].count=1;
            sta[i].pk_number=g_packetnum;
            sta[i].dbm=dbm;
            sprintf(src_mac,"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",stmac[0],stmac[1],stmac[2],stmac[3],stmac[4],stmac[5]);
            // printf("src_mac=%s\tmac_count=%d\tdbm_offset=%d\tdbm=%d\tg_packetnum=%d\tpkthdr.len=%d\n",src_mac,mac_count,dbm_offset,dbm,g_packetnum,pkthdr.len);
            printf("src_mac=%s\tdbm=%d\tmac_count=%d\tg_packetnum=%d\n",src_mac,dbm,mac_count,g_packetnum);
        }
    }


   /* if(ntohs(pt_logical_linkctl->type) !=0x0800)  //过滤掉非IP数据包
    {
        return;
    }
    
    pktdata_temp = pktdata_temp + 8; //跳过Logical Link Control
    pt_ip_header = (IPHeader_t *)pktdata_temp;
    if(pt_ip_header->Protocol !=0x0006)  //过滤掉非TCP数据包
    {
        return;
    }

    inet_ntop(AF_INET, (void *)&(pt_ip_header->SrcIP), src_ip, 16);
    inet_ntop(AF_INET, (void *)&(pt_ip_header->DstIP), dst_ip, 16);
    data_record.src_ip = pt_ip_header->SrcIP;
    data_record.dst_ip = pt_ip_header->DstIP;
     
    iphead_len = pt_ip_header->ihl * 4;  //计算ip头长度
    iptotal_len = ntohs(pt_ip_header->TotalLen);
    //printf("iptotal_len= %d\n", iptotal_len);
    
    pktdata_temp = pktdata_temp +iphead_len; //跳过 IP头部
    pt_tcp_header = (TCPHeader_t *) pktdata_temp;
    
    src_port = ntohs(pt_tcp_header->SrcPort);
    dst_port = ntohs(pt_tcp_header->DstPort);
    
    strftime(my_time, sizeof(my_time), "%Y-%m-%d %T", localtime(&(pkthdr.ts.tv_sec)));     //获取时间
    //打印抓取包的时间
    printf("%s\n", my_time);

    gettimeofday(&current_time, NULL);
    data_record.currenttime_sec = current_time.tv_sec;
    data_record.currenttime_msec = current_time.tv_usec / 1000;*/
        
    /*printf("src_mac=%s dst_mac=%s \nsrc_ip=%s dst_ip=%s \nsrc_port=%d dst_port=%d\n",src_mac, dst_mac, src_ip,dst_ip, src_port,dst_port);
    
    if(dst_port != 80 && dst_port != 8080)  //过滤掉非http包
    {
        return;
    }
    
    tcphead_len = pt_tcp_header->thl * 4;  //计算tcp头部长度
    pktdata_temp = pktdata_temp +tcphead_len;  //跳过 TCP头部
    process_one_http_packet(pktdata_temp, iptotal_len-iphead_len-tcphead_len, &data_record);
    printf("\n");*/
#endif
    return;    
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
/*---------------------------------------------------------------*/
    //copy
#if 0
    mac_count2=mac_count;
    ap_count2=ap_count;
    memcpy(sta2,sta,mac_count2*sizeof(STA_S));
    memcpy(ap2,ap,ap_count2*sizeof(AP_S));


    g_packetnum=0;
    mac_count=0;
    ap_count=0;
    memset(ap,0,ap_count2*sizeof(AP_S));
    memset(sta,0,mac_count2*sizeof(STA_S));

    pcap_handle = pcap_open_offline(argv[2],errbuf);
    if(pcap_handle == NULL)
    {
        printf("open file2 failed : %s\n",errbuf);

        exit(1);
    }
    while ((pktdata = pcap_next(pcap_handle,&pkthdr)) != NULL){
        g_packetnum++;
        process_one_wireless_cap_packet(pktdata, pkthdr);
    }
    pcap_close(pcap_handle);

    //compare
    printf("ap_count2=%d\t%d\t%d\t%d\n",ap_count2,mac_count2,ap_count,mac_count);
    for(i=0;i<ap_count2;i++){
        for(j=0;j<ap_count;j++){
               // printf("tests\n");
            if(memcmp(ap2[i].bssid,ap[j].bssid,6)==0){
                ap2[i].flag=1;
                pri_ap_count2++;
                break;
            }
        }
    }

    for(i=0;i<mac_count2;i++){
        for(j=0;j<mac_count;j++){
            if(memcmp(sta2[i].mac,sta[j].mac,6)==0){
                sta2[i].flag=1;
                pri_mac_count2++;
                break;
            }
        }
    }

    for(i=0;i<ap_count;i++){
        for(j=0;j<ap_count2;j++){
            if(memcmp(ap[i].bssid,ap2[j].bssid,6)==0){
                ap[i].flag=1;
                pri_ap_count++;
                break;
            }
        }
    }

    for(i=0;i<mac_count;i++){
        for(j=0;j<mac_count2;j++){
            if(memcmp(sta[i].mac,sta2[j].mac,6)==0){
                sta[i].flag=1;
                pri_mac_count++;
                break;
            }
        }
    }

    char	name[4096];
    FILE 	* fl;
    i = snprintf(name, 150, "%s%s", argv[1], ".xls"); //
    fl = fopen (name, "w+");
    if (! fl) {
            printf("creat file1 error\n");
            return 1;
    }

    snprintf(name,4096,"%s\n",argv[1]);
    len=fwrite(name, 1, strlen(name), fl);
    for(i=0;i<ap_count2;i++){
        snprintf(name,4096,"bssid=%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\t%s\tcount=%d\tdbm=%d\tfirst_pk_num=%d\n",ap2[i].bssid[0],ap2[i].bssid[1],ap2[i].bssid[2],ap2[i].bssid[3],ap2[i].bssid[4],ap2[i].bssid[5],((ap2[i].flag==0)?"private":"public"),\
                  ap2[i].count,ap2[i].dbm,ap2[i].pk_number);
        len=fwrite(name, 1, strlen(name), fl);
    }


    for(i=0;i<mac_count2;i++){
        snprintf(name,4096,"mac=%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\t%s\tcount=%d\tdbm=%d\tfirst_pk_num=%d\n",sta2[i].mac[0],sta2[i].mac[1],sta2[i].mac[2],sta2[i].mac[3],sta2[i].mac[4],sta2[i].mac[5],((sta2[i].flag==0)?"private":"public"),\
                 sta2[i].count,sta2[i].dbm,sta2[i].pk_number);
        len=fwrite(name, 1, strlen(name), fl);
    }

    snprintf(name,4096,"%s\n",argv[2]);
    len=fwrite(name, 1, strlen(name), fl);
    for(i=0;i<ap_count;i++){
        snprintf(name,4096,"bssid=%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\t%s\tcount=%d\tdbm=%d\tfirst_pk_num=%d\n",ap[i].bssid[0],ap[i].bssid[1],ap[i].bssid[2],ap[i].bssid[3],ap[i].bssid[4],ap[i].bssid[5],((ap[i].flag==0)?"private":"public"),\
                 ap[i].count,ap[i].dbm,ap[i].pk_number);
        len=fwrite(name, 1, strlen(name), fl);
    }


    for(i=0;i<mac_count;i++){
        snprintf(name,4096,"mac=%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\t%s\tcount=%d\tdbm=%d\tfirst_pk_num=%d\n",sta[i].mac[0],sta[i].mac[1],sta[i].mac[2],sta[i].mac[3],sta[i].mac[4],sta[i].mac[5],((sta[i].flag==0)?"private":"public"),\
                 sta[i].count,sta[i].dbm,sta[i].pk_number);
        len=fwrite(name, 1, strlen(name), fl);
    }

    i = snprintf(name, 150, "file1 pri_ap_count=%d\tfile1 pri_mac_count=%d\tfile2 pri_ap_count=%d\tfile2 pri_mac_count=%d\n", ap_count2-pri_ap_count2,mac_count2-pri_mac_count2,ap_count-pri_ap_count,mac_count-pri_mac_count); //
    len=fwrite(name, 1, strlen(name), fl);
    printf(name);
    i = snprintf(name, 150, "public_ap_count=%d\tpublic_mac_count=%d\n", pri_ap_count2,pri_mac_count2); //
    len=fwrite(name, 1, strlen(name), fl);
    printf(name);
    fclose(fl);
#endif
    return 0;
}

