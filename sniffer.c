/*
Author: Martin Pentrak
Date: apr 24 2022 19:27
*/


#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdbool.h>
#include <string.h>
#include <pcap.h>
#include <time.h>

#define SIZE_ETHERNET 14
#define UDP_HEADER 8
#define IP_PROTOCOL 8
#define TCP_PROTOCOL 6
#define UDP_PROTOCOL 17
#define ICMP_PROTOCOL 1
#define TCP     0
#define UDP     1
#define ARP     2
#define ICMP    3 
#define IP6_PROTOCOL 56710
#define ARP_PROTOCOL 1544
/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};
/* IP header */
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

struct IPv4_address{
    u_int8_t first_part;
    u_int8_t second_part;
    u_int8_t third_part;
    u_int8_t fourth_part;
};

struct sniff_udp {
	u_short udp_sport;	/* source port */
	u_short udp_dport;	/* destination port */
    u_short udp_len;        /*udp len*/
	u_short udp_sum;		/* checksum */

};

struct sniff_icmp {
	u_char icmp_type;	    /* type */
	u_char icmp_code;	    /* error code */
    u_short icmp_checksum;  /*checksum */

};

struct sniff_icmp6 {
	u_char icmp_type;	    /* type */
	u_char icmp_code;	    /* error code */
    u_short icmp_checksum;  /*checksum */
    u_short icmp_ID;
    u_short icmp_SEQ_N;
};

struct sniff_arp {
	u_short hw_type;	
    u_short arp_prot;	
    u_char HA_LEN;        /*hw  address len*/
	u_char PA_LEN;		/* physical address len*/
    u_short operation_code;
};

struct sniff_arpv4
{
    u_char src_HW[6]; 
    u_char src_IP[4]; 
    u_char dst_HW[6]; 
    u_char dst_IP[4]; 
};
struct sniff_arpv6
{
    u_char src_HW[6]; 
    u_int16_t src_IP[8]; 
    u_char dst_HW[6]; 
    u_int16_t dst_IP[8]; 
};

struct sniff_ip6 {
	u_char ip_vtc;      //version 0-4 TC 4>	
    u_short ip_tclab;
    u_char ip_label;
    u_short payload_len;
    u_char nex_head;
    u_char hop_lim;
    u_int source_address[4];
    u_int destination_address[4];
};

struct ipv6
{
    u_short source_addr[8];
    u_short destination_addr[8];
};



struct port_list{
    int port_number;
    struct port_list *next;
};

void write_out_inter(int argc,const char* argv[]) //function write out all avaliable devices
{
    pcap_if_t *all_devs; //list of devices
    char error_buff[100];
    all_devs=(pcap_if_t *)malloc(sizeof(pcap_if_t));
    
    pcap_findalldevs(&all_devs,error_buff);
    while (all_devs!=NULL) //print devicess
    {
        printf("%s\n",all_devs->name);
        all_devs=all_devs->next;
    }
    pcap_freealldevs(all_devs);
}


void write_out_error()
{
    printf("error occured");
}


void error_input()
{
    printf("error occured");
}

void   create_filter_expression(char *filter_exp,bool protocols[],char *port) //function creates filter expression
{
    bool first=true;

    printf("first if\n");
    if(protocols[TCP])
    {   
        printf("befpre first\n");
        if(first)
        {
            first=false;
            if(port==NULL)
            {

                filter_exp=strcat(filter_exp,"tcp");
            }
            else
            {
                filter_exp=strcat(filter_exp,"(tcp and port ");
                filter_exp=strcat(filter_exp,port);
                filter_exp=strcat(filter_exp,")");
            }
        }
    }
    if(protocols[UDP])
    {   
        if(first)
        {
            first=false;
            if(port==NULL)
            {
                filter_exp=strcat(filter_exp,"udp");
            }
            else
            {
                filter_exp=strcat(filter_exp,"(udp and port ");
                filter_exp=strcat(filter_exp,port);
                filter_exp=strcat(filter_exp,")");
            }
        }
        else
        {
            if(port==NULL)
            {
                filter_exp=strcat(filter_exp," or udp");
            }
            else
            {
                filter_exp=strcat(filter_exp," or (udp and port ");
                filter_exp=strcat(filter_exp,port);
                filter_exp=strcat(filter_exp,")");
            }   
        }
    }
    if(protocols[ICMP])
    {   
        if(first)
        {
        filter_exp=strcat(filter_exp,"icmp");
        first=false;
        }
        else
        {
            filter_exp=strcat(filter_exp," or icmp");

        }
    }
        
    if(protocols[ARP])
    {   
        if(first)
        {
        filter_exp=strcat(filter_exp,"arp");
        first=false;
        }
        else
        {
            filter_exp=strcat(filter_exp," or arp");

        }
    }
}



void got_packet(u_char *args,const struct pcap_pkthdr *header,const u_char *packet)
{
    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip; /* The IP header */
    const struct sniff_ip6 *ip6; /* The IP header */
    const struct sniff_icmp6 *icmp6; /*icmpv6 header*/
    const struct sniff_tcp *tcp; /* The TCP header */
    const struct sniff_udp *udp; /* The UDP header */
    const struct sniff_udp *icmp; /* The UDP header */
    const struct sniff_arp *arp;
    const struct sniff_arpv4 *arpv4;
    const struct sniff_arpv6 *arpb6;

    char time[100];
    char ms[100]; //miliseconds
    char *str_buf;
    const char *payload; /* Packet payload */
    u_int size_ip6=40;
    u_int size_icmp6;
    u_int size_ip;
    u_int8_t size_tcp;
    u_int size_udp;
    u_int size_icmp;
    
    ethernet = (struct sniff_ethernet*)(packet);
    time_t raw=header->ts.tv_sec;
    struct tm *info;
    info = localtime(&raw);
    strftime(time, sizeof(time), "%Y-%m-%dT%H:%M:%S",info);
    sprintf(ms, "%ld", header->ts.tv_usec/1000);
    str_buf=time;
    str_buf=strcat(time,".");
    str_buf=strcat(time,ms);
    str_buf=strcat(time,"+01:00");
    printf("timestamp: %s\n",time);
    printf("src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5]);
    printf("dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",ethernet->ether_dhost[0],ethernet->ether_dhost[1],ethernet->ether_dhost[2],ethernet->ether_dhost[3],ethernet->ether_dhost[4],ethernet->ether_dhost[5]);
    u_int frame_len=header->len;
    printf("frame length: %d\n",frame_len);
    //printf("Local Time %s\n", time);
    if(ethernet->ether_type==IP_PROTOCOL)//IP
    {
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;

        int p_header_size;
        u_int32_t rev_addr_dst;  //print out ip adresses 
        u_int32_t rev_addr_src;
        struct IPv4_address *src_address;
        rev_addr_src=ip->ip_src.s_addr;
        src_address=(struct IPv4_address*)(&rev_addr_src); //reverse
        struct IPv4_address *dst_address;
        rev_addr_dst=ip->ip_dst.s_addr;
        dst_address=(struct IPv4_address*)(&rev_addr_dst); //reverse
        printf("src IP: %d.%d.%d.%d\n",src_address->first_part,src_address->second_part,src_address->third_part,src_address->fourth_part);//OK but reverse
        printf("dst IP: %d.%d.%d.%d\n",dst_address->first_part,dst_address->second_part,dst_address->third_part,dst_address->fourth_part);//OK but reverse
       
        if (size_ip < 20) {
	        printf("   * Invalid IP header length: %u bytes\n", size_ip);
            return;
        }
        if(ip->ip_p==TCP_PROTOCOL) //tcp
        {
            
            tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
            size_tcp = TH_OFF(tcp);
            size_tcp =size_tcp*4;
            if (size_tcp < 20) {
                printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
                return;
            }
            u_int16_t src_port=ntohs(tcp->th_sport);
            printf("src_prt: %d\n",src_port);   
            u_int16_t dst_port=ntohs(tcp->th_dport);
            printf("dst_prt: %d\n",dst_port);
            payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp); 
            p_header_size=size_tcp;       
        }
        else if(ip->ip_p==UDP_PROTOCOL){
            
            udp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
            size_udp = UDP_HEADER;

            u_int16_t src_port=ntohs(udp->udp_sport);
            printf("src_prt: %d\n",src_port);   
            u_int16_t dst_port=ntohs(udp->udp_dport);
            printf("dst_prt: %d\n",dst_port);
            payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp); 
            p_header_size=size_udp;
        
        }
        else if(ip->ip_p==ICMP_PROTOCOL)
        {
            icmp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
            size_icmp = UDP_HEADER; //it is same as ICMP 
            payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_icmp); 
            p_header_size=size_icmp;
        }
        int packet_len=ntohs(ip->ip_len);
        int chars_counter=0;

        printf("\n");
        u_int32_t offset=0;
        for (int j=0;j<packet_len-(size_ip+p_header_size);j++)
        {
            if(j==0)
            {
                printf("0x%04x\t",offset);
            }
            u_char hex=payload[j];
            printf("%02x ",hex);
            if((chars_counter==15) || (j+1)==packet_len-(size_ip+p_header_size))
            {
                printf("\t");
                int chars2_counter=0;
                for(int i=j-chars_counter;i<packet_len-(size_ip+p_header_size);i++)
                {
                    if(payload[i]>=32 && payload[i]<=126)
                    {
                        printf("%c",payload[i]);
                    }
                    else
                    {
                        printf(".");
                    }
                    if(chars2_counter==chars_counter)
                    {
                        break;
                    }
                    chars2_counter++;
                }  
                offset=offset+16;
                printf("\n"); 
                if((j+1)!=packet_len-(size_ip+p_header_size)) 
                    printf("0x%04x\t",offset);
                chars_counter=0;

                continue;    
            }
            chars_counter++;
        }
    }
    else if(ethernet->ether_type==IP6_PROTOCOL)//IPv6wis
    {
        size_ip=40;
        size_ip6=40;
        ip6 = (struct sniff_ip6*)(packet + SIZE_ETHERNET);

        const struct ipv6 *address;

        address= (struct ipv6*)ip6->source_address;

        printf("src IP: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",address->source_addr[0],address->source_addr[1],address->source_addr[2],address->source_addr[3],address->source_addr[4],address->source_addr[5],address->source_addr[6],address->source_addr[7]);//OK but reverse
        printf("dst IP: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",address->destination_addr[0],address->destination_addr[1],address->destination_addr[2],address->destination_addr[3],address->destination_addr[4],address->destination_addr[5],address->destination_addr[6],address->destination_addr[7]);//OK but reverse

        int p_header_size;
        if(ip6->nex_head==TCP_PROTOCOL) //tcp
        {
            tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
            size_tcp = TH_OFF(tcp);
            size_tcp =size_tcp*4;
            if (size_tcp < 20) {
                printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
                return;
            }
            u_int16_t src_port=ntohs(tcp->th_sport);
            printf("src_prt: %d\n",src_port);   
            u_int16_t dst_port=ntohs(tcp->th_dport);
            printf("dst_prt: %d\n",dst_port);
            payload = (u_char *)(packet + SIZE_ETHERNET + size_ip6 + size_tcp);     
            p_header_size=size_tcp;       
   
        }
        else if(ip6->nex_head==UDP_PROTOCOL){
            
            udp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip6);
            size_udp = UDP_HEADER;
            u_int16_t src_port=ntohs(udp->udp_sport);
            printf("src_prt: %d\n",src_port);   
            u_int16_t dst_port=ntohs(udp->udp_dport);
            printf("dst_prt: %d\n",dst_port);
            payload = (u_char *)(packet + SIZE_ETHERNET + size_ip6 + size_udp); 
            p_header_size=size_udp;
        }
        else if(ip6->nex_head==ICMP_PROTOCOL)
        {
            icmp6 = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip6);
            size_icmp6 = UDP_HEADER;
            payload = (u_char *)(packet + SIZE_ETHERNET + size_ip6 + size_icmp6); 
            p_header_size=size_icmp;
        }  
        int packet_len=ntohs(ip6->payload_len);
        int chars_counter=0;

        printf("\n");
        u_int32_t offset=0;
        for (int j=0;j<packet_len-(size_ip+p_header_size);j++)
        {
            if(j==0)
            {
                printf("0x%04x\t",offset);
            }
            u_char hex=payload[j];
            printf("%02x ",hex);
            if((chars_counter==15) || (j+1)==packet_len-(size_ip+p_header_size))
            {
                printf("\t");
                int chars2_counter=0;
                for(int i=j-chars_counter;i<packet_len-(size_ip+p_header_size);i++)
                {
                    if(payload[i]>=32 && payload[i]<=126)
                    {
                        printf("%c",payload[i]);
                    }
                    else
                    {
                        printf(".");
                    }
                    if(chars2_counter==chars_counter)
                    {
                        break;
                    }
                    chars2_counter++;
                }  
                offset=offset+16;
                printf("\n"); 
                if((j+1)!=packet_len-(size_ip+p_header_size)) 
                    printf("0x%04x\t",offset);
                chars_counter=0;

                continue;    
            }
            chars_counter++;
        }
    }
    else if (ethernet->ether_type==ARP_PROTOCOL)//ARP
    {
            arp = (struct sniff_arp*)(packet + SIZE_ETHERNET);
            int size_arp=8;
            if(arp->PA_LEN==4)
            {
                arpv4=(struct sniff_arpv4*)(packet+SIZE_ETHERNET+size_arp);
        
           
                printf("src IP: %d.%d.%d.%d\n",arpv4->src_IP[0],arpv4->src_IP[1],arpv4->src_IP[2],arpv4->src_IP[3]);//OK but reverse
                printf("dst IP: %d.%d.%d.%d\n",arpv4->dst_IP[0],arpv4->dst_IP[1],arpv4->dst_IP[2],arpv4->dst_IP[3]);//OK but reverse

            }
            else
            {
                arpb6=(struct sniff_arpv6*)(packet + SIZE_ETHERNET+size_arp);

                printf("src IP: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",arpb6->src_IP[0],arpb6->src_IP[1],arpb6->src_IP[2],arpb6->src_IP[3],arpb6->src_IP[4],arpb6->src_IP[5],arpb6->src_IP[6],arpb6->src_IP[7]);//OK but reverse
                printf("dst IP: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",arpb6->dst_IP[0],arpb6->dst_IP[1],arpb6->dst_IP[2],arpb6->dst_IP[3],arpb6->dst_IP[4],arpb6->dst_IP[5],arpb6->dst_IP[6],arpb6->dst_IP[7]);//OK but reverse

            }
    }
    else
    {
        error_input();
    }
    printf("\n");
    return;
}

int main(int argc,char **argv)
{
    char *opt_string="iputn"; //string for short options
    bool protocols[4]={false}; //the field where filtered protocols are stored 
    char errbuf[100];

    static struct option options[] = { //long options
        {"interface",optional_argument, NULL, 'i'},
        {"tcp",  no_argument, NULL, 't'},
        {"udp",  no_argument, NULL, 'u'},
        {"arp",  no_argument, NULL, 0},
        {"icmp", no_argument, NULL, 0},
        {NULL, 0, NULL, 0}
    };
    struct port_list *head; //list of ports to be filtered 
    head=(struct port_list*)malloc(sizeof(struct port_list));

    char *interface; //on which interface we are sniffing
    int opt_index=0; //default value to start on first option
    int short_option;
    int number_of_packets=1;
    char *port_number=NULL;
    bool interface_set=false;
    while((short_option=getopt_long(argc,argv,opt_string,options,&opt_index))!=-1)
    {
        switch (short_option) //find out options and stores them 
        {
        case 'i':
            interface_set=true;
            if(argv[optind]!=NULL)
            {
                if(argv[optind][0]!='-')// think about something better what if --- somebody insert 3-
                {
                    interface=argv[optind];
                }
            }
            else
            {
                write_out_inter(argc,argv);
                return -1;
            }
            break;
        case 'p':
            if(argv[optind][0]!='-')// think about something better what if --- somebody insert 3-
            {
                port_number = argv[optind]; //add check if it is a number 
            }
            else
            {
                write_out_error();
                return -1;
            } 
            break;
        case 'n':
            if(argv[optind][0]!='-')// think about something better what if --- somebody insert 3-
            {
                
               if((number_of_packets=atoi(argv[optind]))==-1)
               {
                   number_of_packets=number_of_packets;
                   //exit with error code or some shit 
               }
            }
            else
            {
                write_out_error();
                return -1;
            }
            break;
        case 't': //check if it is something after it if yes end program like if it is not next argument 
            protocols[TCP]=true;
            break;
        case 'u'://check if it is something after it if yes end program like if it is not next argument 
            protocols[UDP]=true;
            break; 
        case '?':
            error_input();
            return -1;
            break;
        default: //if it is long option 
            if(strcmp("arp",options[opt_index].name)==0)
            {
                protocols[ARP]=true;
            }
            else if (strcmp("icmp",options[opt_index].name)==0)
            {
                protocols[ICMP]=true;
            }
            else
            {
                error_input();
            }
            break;
        }
    }
    if(!interface_set)
    {
        write_out_inter(argc,argv);
        return(-1);
    }
    
    pcap_t *handle; //frame handle
    char *filter_exp; //filter_exp
    filter_exp=malloc(sizeof(char));
    create_filter_expression(filter_exp,protocols,port_number);//create expression for filter 
    struct pcap_pkthdr header;	/* The header that pcap gives us */
    bpf_u_int32 mask;		/* The netmask of our sniffing device */
    bpf_u_int32 net;		/* The IP of our sniffing device */
   // const u_char *packet;	
    struct bpf_program  fp;
    if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
    	fprintf(stderr, "Can't get netmask for device %s\n", interface);
    	net = 0;
    	mask = 0;
    }
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
    	fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
    	return(2);
    }
    if (pcap_datalink(handle) != DLT_EN10MB) { //check if it is ethernet header 
	    fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", interface);
	    return(2);
    }
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    	fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    	return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
    	fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    	return(2);
    }
    int a;
    a=pcap_loop(handle,number_of_packets,got_packet,NULL);
}
