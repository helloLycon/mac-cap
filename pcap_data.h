#ifndef __PCAP_DATA_H__
#define __PCAP_DATA_H__

//#define LITTLE_ENDIAN WORDS_BIGENDIAN

//#define BUFSIZE 10240
#define FALSE 0
#define TRUE  1

#define STRSIZE 100
#define MAX_URL_LEN 256
#define MAX_HOST_LEN 50
#define RECV_PACKET_MAX_OUTTIME 60          /* ձʱʱ */
#define SEND_PACKET_MAX_OUTTIME 60          /* ͱʱʱ */
#define SEND_PACKET_MAX_NUM     1           /* ͱۼ */
#define GET_FILE_LINE_MAX_SIZE  256         /* ȡļһֽ */
#define RECV_PACKET_SIZE        1024        /* һĵĳ */
#define DATA_RECORD_LEN         37          /* һݼ¼ĳ() */
#define SEND_PACKET_MAX_LEN     10 * 1024   /* ͱ󳤶 */

#define COMMAND_PHONE_DATA      0x3000  /* ʾݰ */
#define COMMAND_REG             0x1000  /* 豸�?*/
#define COMMAND_REG_RESPONSE    0x1001  /* Ӧע */
#define GET_FILE_MAX_SIZE           256                             /* ȡļ󳤶 */
#define CMD_MAX_SIZE                        256     /* 󳤶 */

#define DEVICE_ID_FILE      "/home/config/device_id.txt"    /* 豸Ŵ洢ļ */
#define DEVICE_ID_INT       "id_int"                        /* int ʾid  */
#define SERVICE_INFO_FILE   "/home/config/service_info"            /* ַ洢�?*/
#define IFCONFIG_TEMP               "/var/ifconfig_temp"            /* ʱ洢ifconfig Ϣļ */

typedef unsigned short  u_short;
typedef unsigned long    u_int32;
typedef unsigned short    u_int16;
typedef unsigned char    u_int8;


typedef enum
{
    GET = 1,
    POST = 2,
    OTHER =3
}HTTP_FLAG;

/* ץ */
typedef enum catch_data_type
{
    CATCH_DATA_TYPE_QQ = 0,     /* qq  */
    CATCH_DATA_TYPE_IMSI = 1,   /* IMSI */
    CATCH_DATA_TYPE_URL = 2,    /* URL */

    CATCH_DATA_TYPE_MAX
}catch_data_type;

/* Ĵͷ */
typedef enum packet_send_direction
{
    PACKET_SEND_DIRECTION_EXIT = 0, /* ķͳȥ */
    PACKET_SEND_DIRECTION_ENTER = 1,/* Ĵͽ */    

    PACKET_SEND_DIRECTION_MAX
}packet_send_direction;

//mac ͷݽ�?
struct ether_header{
    u_int8_t ether_dhost[6];
    /*Ŀַ̫*/
    u_int8_t ether_shost[6];
    /*Դ ַ̫*/
    u_int16_t ether_type;    
    /*̫*/
};


typedef u_int32_t in_addr_t;
/*
struct in_addr{
    in_addr_t s_addr;
};
*/
//ip ͷݽ�?

struct ip_header
{
#ifdef WORDS_BIGENDIAN
    u_int8_t ip_version:4;
    /*ip �?/
    u_int8_t ip_header_length:4;
    /*ײ*/    
#else
    u_int8_t ip_header_length:4;
       /* ײ*/
    u_int8_t ip_version:4;
#endif
    u_int8_t ip_tos;
    /**/
    u_int16_t ip_length;
    /*ݰ*/
    u_int16_t ip_id;
    /*ʶ*/
    u_int16_t ip_off;
    /*ݰƫ*/
    u_int8_t ip_ttl;
    /*ʱ*/
    u_int8_t ip_protocol;
    /*ip ݰЭ*/
    u_int16_t ip_checksum;
    /**/
    struct in_addr ip_source_address;
    /*Դַip */
    struct in_addr ip_destination_address;
    /*Ŀĵַip*/
};

//arpͷݽ�?
struct arp_header{
    u_int16_t arp_hardware_type;
    /*Ӳ*/
    u_int16_t arp_protocol_type;
    /*Э*/
    u_int8_t arp_hardware_length;
    /*Ӳ*/
    u_int8_t arp_protocol_length;
    /*Э�?/
    u_int16_t arp_operation_code;
    /**/
    u_int8_t arp_source_ethernet_address[6];
    /*Դ ַ̫*/
    u_int8_t  arp_source_ip_address[4];
    /*Դ ipַ*/
    u_int8_t arp_destination_ethernet_address[6];
    /*Ŀַ̫*/
    u_int8_t arp_destination_ip_address[4];
    /*Ŀip ַ*/
};

//tcp ͷݽ�?
struct tcp_header{
    u_int16_t tcp_source_port;
    u_int16_t tcp_destination_port;
    u_int32_t tcp_acknowledgement;
    u_int32_t tcp_ack;
#ifdef WORDS_BIGENDIAN
    u_int8_t tcp_offset:4;
    u_int8_t tcp_reserved:4;
#else 
    u_int8_t tcp_reserved:4;
    u_int8_t tcp_offset:4;
#endif
    u_int8_t tcp_flags;
    u_int16_t tcp_windows;
    u_int16_t tcp_checksum;
    u_int16_t tcp_urgent_pointer;
};

// udp ͷݽ�?
struct udp_header{
    u_int16_t udp_source_port;
    u_int16_t udp_destination_port;
    u_int16_t udp_length;
    u_int16_t udp_checksum;
};
//icmp ͷݽ�?
struct icmp_header
{
    u_int8_t icmp_type;
    u_int8_t icmp_code;

    u_int16_t icmp_checksum;
    u_int16_t icmp_identifier;
    u_int16_t icmp_sequence;
};


typedef struct 
{
    u_int16 framectl;          /*Frame Control*/
    u_int16 duration;           /*Duration ID*/
    u_int8 bssidmac[6];          /* bssid mac address             */
    u_int8 srcmac[6];            /* source mac address           */
    u_int8 dstmac[6];            /* destination mac address         */
    u_int16 seqnum;             /* sequence number             */   
}IEEE_802_11_info   ;  //ܺ802.11 ݰͷ

typedef struct
{
    u_int8 eh_dst[6]; /* destination ethernet addrress */ 
    u_int8 eh_src[6]; /* source ethernet addresss */ 
    u_int16 eh_type; /* ethernet pachet type */
}EthHeader;  //̫ͷ�?


typedef struct
{
    u_int8 dsap;
    u_int8 ssap;
    u_int8 ctlfield;
    u_int8  orgcode[3];
    u_int16  type;    

}Logical_Link_Ctl;  //߼·ƽ�?

//IPݱͷ
typedef struct 
{     //IPݱͷ
    //u_int8     Ver_HLen;    //�?ͷ
    #if LITTLE_ENDIAN
    u_int8 ihl:4;
    u_int8 version:4;
    #else
       u_int8 version:4;//汾źͷǻĹϵλòȷôдʹϵͳԶ�?
    u_int8 ihl:4;
    #endif
    
    u_int8     TOS;    //
    u_int16     TotalLen;    //ܳ
    u_int16     ID;             //ʶ
    u_int16     Flag_Segment;    //־+Ƭƫ
    u_int8     TTL;    //
    u_int8     Protocol;    //Э
    u_int16     Checksum;    //ͷУ
    u_int32     SrcIP;              //ԴIPַ
    u_int32     DstIP;              //ĿIPַ
} IPHeader_t;


//TCPݱͷ
typedef struct 
{    
    u_int16     SrcPort;     //Դ˿
    u_int16     DstPort;     //ĿĶ˿
    u_int32     SeqNO;          //
    u_int32     AckNO;         //ȷϺ    
    #if LITTLE_ENDIAN
    u_int8 reserved_1:4;
    u_int8 thl:4;//ײ
    u_int8 flag:6;
    u_int8 reserved_2:2;
    #else
    u_int8 thl:4;
    u_int8 reserved_1:4;
    u_int8 reserved_2:2;
    u_int8 flag:6;
    #endif
    
    u_int16     Window;     //ڴС
    u_int16     Checksum;     //У
    u_int16     urgt_p;    //ָ
    
}TCPHeader_t;    //TCPݱͷ

/* ݱͷ */
typedef struct phone_data_head
{
    u_int32 device_id;  /* 豸id */
    u_int32 connid;     /*  */
    u_int8  packet_num; /*  */
}phone_data_head;

/* ݱ */
typedef struct phone_data
{
    u_int16 data_len;           /* ĵĳȣ */
    u_int8  data_type;          /* Ͳμcatch_data_type */
    u_int8  value_len;          /* ݳ */
    char    value[256];         /*  */
    u_int32 intime_sec;         /* ʱ侫�?*/
    u_int16 intime_msec;        /* ʱĺ */
    u_int32 outtime_sec;        /* ˳ʱ侫�?*/
    u_int16 outtime_msec;       /* ˳ʱĺ */
    u_int8  src_mac[6];         /* ĵԴmac ַ */
    u_int8  dst_mac[6];         /* ĵĿmac ַ */
    u_int32 src_ip;             /* ĵԴip ַ */
    u_int32 dst_ip;             /* ĵĿip ַ */
    u_int8  act;                /* ĵĴͷμpacket_send_direction */

    u_int32 currenttime_sec;    /* ǰʱ侫�?*/
    u_int16 currenttime_msec;   /* ǰʱĺ */
    u_int8  flag;               /* ʾǰ¼ĻԾ״̬ */
    
    struct phone_data *next;    /* ָһ */
}phone_data;

extern void encapsulated_data_head();

#endif /* __PCAP_DATA_H__ */

