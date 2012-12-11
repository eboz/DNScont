/*
 * DNScont 1.0
 *
 * by eboz
 * send your bugs and complains to eb0z@hotmail.com
 *
 * a pseudo DNS script that uses stateless TCP
 *
 * the assumption here is that the host system
 * - uses an ethernet interface
 * - does not already run a listener on tcp port 53
 * - does not use the kernel blackhole facility. i.e.
 *    sysctl -w net.inet.tcp.blackhole=2
 *    sysctl -w net.inet.udp.bkackhole=1
 *
 * the routine uses the libpcap libraries (www.tcpdump.org)
 * and the IP raw socket interface to fake out a tCP 
 * connection
 *
 * it uses a UDP connection to a backend DNS server
 *
 * this is very much a crude proof of concept exercise - it does not
 * attempt to interpret any flags about transport or buffer size
 * or react to truncated responses - it simply maps the TCP query to a UDP
 * query (by stripping out the query size leading field) and maps the UDP 
 * response to a TCP response (by adding the same length field back in)
 * Doubtless the entire mapping function could be improved, but it really
 * wasn't the intention to make this into a robust DNS proxy. The intention
 * was to show that TCP DNS client queries could be served from a stateless
 * TCP server. 
 *
 * compilation:
 *  gcc -lpcap -o DNScont DNScont.c
 *
 * execution: 
 *  sudo dnscont <Interface_device_name>
 *
 * this program uses constants for the local IP address and backend servers 
 * change them, can be useful in hijacking sessions
 */

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#define THIS_HOST "10.0.0.1"
#define PORT 53

#define BACK_HOST  "dns.server"                 /* DNS back end server */
#define BACK_PORTNO  53                         /* UDP port number of backend server */
#define PCKT_LEN   1024                         /* max size of sent packet */
#define BUFSIZE   16384                         /* buffer size */
#define RESPSIZE    512                         /* max size of each TCP payload in response */
#define MAXSEGL    1220                         /* TCP max MSS response size */
#define TCP_PROTOCOL  6                         /* TCP protocol identifier value */




/*******************************************************************
 *
 * Ethernet
 *
 */

/* default Ethernet snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are 14 bytes */
#define SIZE_ETHERNET 14



/*******************************************************************
 *
 * IP
 *
 * this is found in  <netinet/in.h>, but I'll reproduce it here
 * for clarity.
 */

/* IP header */
struct ip_hdr {
  u_char  ip_vhl;                            /* version << 4 | header length >> 2 */
#define IP_HL(ip)    (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)     (((ip)->ip_vhl) >> 4)
  u_char  ip_tos;                            /* type of service */
  u_short ip_len;                            /* total length */
  u_short ip_id;                             /* identification */
  u_short ip_off;                            /* fragment offset field */
#define IP_RF 0x8000                         /* reserved fragment flag */
#define IP_DF 0x4000                         /* dont fragment flag */
#define IP_MF 0x2000                         /* more fragments flag */
#define IP_OFFMASK 0x1fff                    /* mask for fragmenting bits */
  u_char  ip_ttl;                            /* time to live */
  u_char  ip_p;                              /* protocol */
  u_short ip_sum;                            /* checksum */
  struct  in_addr ip_src,ip_dst;             /* source and dest address */
  };


/*******************************************************************
 *
 * TCP
 *
 * this is found in <netinet/tcp.h>, but I'll reproduce it here
 * for clarity
 */

/* TCP header */
typedef u_int32_t tcp_seq ;

struct tcp_hdr {
  u_short th_sport;                          /* source port */
  u_short th_dport;                          /* destination port */
  tcp_seq th_seq;                            /* sequence number */
  tcp_seq th_ack;                            /* acknowledgement number */
  u_char  th_offx2;                          /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
  u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
  u_short th_win;                            /* window */
  u_short th_sum;                            /* checksum */
  u_short th_urg;                            /* urgent pointer */
  };

struct tcp_option {
  u_char opt_type ;
  u_char opt_len ;
  u_short opt_val ;
  } ;


/*******************************************************************
 *
 * Global Vars
 *
 */

int sock_fd ;                                 /* socket fd */

/*******************************************************************
 *
 * RAW Socket IP utility functions
 *
 */

/*
 * ip_crc
 *
 * Generate an IP header checksum
 */

u_short
ip_crc(u_short *buf, int nwords)
{
  unsigned long sum;

  for (sum = 0; nwords > 0; nwords--)
    sum += *buf++;

  /* keep only the last 16 bits of the 32 bit calculated sum and add the carries */
  while (sum>>16)
    sum = (sum & 0xFFFF)+(sum >> 16);
  	
  /* Take the one's complement of sum */
  sum = ~sum;

  return((u_short) sum);
}


/*
 * tcp_crc
 *
 * Generate an TCP datagram checksum
 *
 * buff is a pointer to the TCP header and payload data
 * buff_len is the length of buff (octets)
 * data_len is the length of the TCP payload
 * src_addr is a pointer to the source address
 * dest_addr is a pointer to the destination address
 * 
 */

u_short
tcp_crc(u_char *buff, int buff_len, int data_len, u_int32_t *src_addr, u_int32_t *dest_addr)
{
  u_short prot_tcp = 6;
  u_short padd = 0;
  u_short word16;
  u_char *cp ;
  unsigned long sum = 0;	
  int i ;
	

  /* pad the data as necessary to create 16-bit words */
  if (data_len & 1){
    padd=1;
    buff[buff_len]=0;
    }

  /* calculate the sum of all 16 bit words */
  for (i = 0; i < buff_len + padd; i += 2){
    word16 =((buff[i]<<8) & 0xFF00) +(buff[i+1]&0xFF);
    sum = sum + (unsigned long)word16;
    }

  /* add the TCP pseudo header which contains: 
     the IP source and destination addresses, proto number and tcp packet length */


  cp = (u_char *) src_addr ;
  for (i=0;i<4;i=i+2){
    word16 =((cp[i]<<8)&0xFF00)+(cp[i+1]&0xFF);
    sum=sum+word16;	
    }

  cp = (u_char *) dest_addr ;
  for (i = 0; i < 4; i += 2){
    word16 =((cp[i]<<8)&0xFF00)+(cp[i+1]&0xFF);
    sum=sum+word16; 	
    }
  sum = sum + prot_tcp + buff_len;

  /* keep only the last 16 bits of the 32 bit calculated sum and add the carries */
  while (sum>>16)
    sum = (sum & 0xFFFF)+(sum >> 16);
		
  /* Take the one's complement of sum */
  sum = ~sum;

  return ((u_short) sum);
}


/*
 * open_raw_socket
 *
 * open a raw socket interface into the kernel, and let the kernel know
 * that the user app will be completing all the IP header fields.
 */

void
open_raw_socket()
{  
  const int on = 1 ;
  static int sock_opened = 0 ;
  echo "Special thanks to danJoe for originally coding the script in 2001 or 2004."

  if (sock_opened) return ;

  /* create the raw socket */
  if ((sock_fd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
    perror("socket() error");
    exit(EXIT_FAILURE);
    }

  /*Inform the kernel the IP header is already attached */
  if (setsockopt(sock_fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
    perror("setsockopt() error");
    exit(EXIT_FAILURE);
    }
  sock_opened = 1 ;
}


/*******************************************************************
 *
 * Stateless TCP Response routines
 *
 ******************************************************************/

/*****
 *
 * send_tcp_synack
 *
 * In response to an incoming SYN, echo back a SYN+ACK, with the MSS option set to 1220
 *
 * called with a pointer to the IP header
 *
 * Stateless TCP only supports the MSS option
 */

void    
send_tcp_synack(u_char *in_reply_to)
{
  char buffer[PCKT_LEN] ;
  struct ip_hdr *ip_from;                /* the IP headers */ 
  struct ip_hdr *ip_to;
  struct tcp_hdr *tcp_from;              /* The TCP header */
  struct tcp_hdr *tcp_to;
  struct tcp_option *tcp_opt ;
  struct sockaddr_in dst;
  u_char *op;
  int size_ip ;

  /* zero out the buffer space */
  memset(buffer,0,PCKT_LEN) ;

  /* set up the pointers to the received IP packet and the
     IP response packet being assembled here */
  ip_from = (struct ip_hdr *) in_reply_to ;
  ip_to = (struct ip_hdr *) buffer ;

  /* Set up the output IP fields using the received packet's fields,
     flipping the source and destin addresses in the IP header.
     The setting of the DF field is to avoid this null payload
     TCP response having a fragged TCP header. The IP checksum is
     calculated wth a zero value in the checksum field */
  
  ip_to->ip_vhl = ip_from->ip_vhl ;
  ip_to->ip_tos = ip_from->ip_tos ;
  ip_to->ip_len = sizeof(struct ip_hdr) + sizeof(struct tcp_hdr) + sizeof(struct tcp_option) ;
  ip_to->ip_id = htons((u_short) (time(0) & 65535)) ;
  ip_to->ip_off = IP_DF ;
  ip_to->ip_ttl = 255 ;
  ip_to->ip_p = TCP_PROTOCOL ;
  ip_to->ip_sum = 0 ;
  ip_to->ip_src.s_addr = ip_from->ip_dst.s_addr  ;
  ip_to->ip_dst.s_addr = ip_from->ip_src.s_addr  ;

  /* now pull out the received TCP header and also generate a pointer to the output TCP header */
  op = in_reply_to;
  size_ip = IP_HL(ip_from)*4;
  op += size_ip ;
  tcp_from = (struct tcp_hdr *) op;

  op = buffer;
  size_ip = IP_HL(ip_to)*4;
  op += size_ip ;
  tcp_to = (struct tcp_hdr *) op ;

  /* swap the TCP port values, generate a sender sequence number from the time,
     echo back the sender's sequence number (incremented) as the ACK, advertise
     a 65K window and clear the checksum field */
  tcp_to->th_sport = tcp_from->th_dport ;
  tcp_to->th_dport = tcp_from->th_sport ;
  tcp_to->th_seq = htonl((u_int32_t) time(0));
  tcp_to->th_ack = htonl(ntohl(tcp_from->th_seq) + 1) ;
  tcp_to->th_offx2 = (6 << 4);  
  tcp_to->th_flags = (TH_SYN | TH_ACK) ;
  tcp_to->th_win = htons(65535) ;
  tcp_to->th_sum = 0 ;
  tcp_to->th_urg = 0 ;

  /* use a single TCP option, namely a MSS field of 1220 */
  op += 20 ;
  tcp_opt = (struct tcp_option *) op;
  tcp_opt->opt_type = TCPOPT_MAXSEG ;
  tcp_opt->opt_len = TCPOLEN_MAXSEG ;
  tcp_opt->opt_val = htons(MAXSEGL) ;

  /* IP checksum calculation */
  tcp_to->th_sum = htons(tcp_crc((u_char *) tcp_to, sizeof(struct tcp_hdr) + sizeof(struct tcp_option), 0, (uint32_t *) &(ip_to->ip_src.s_addr), (u_int32_t *) &(ip_to->ip_dst.s_addr))) ;

  ip_to->ip_sum = htons(ip_crc((unsigned short *) buffer, 10)) ;

  dst.sin_addr = ip_to->ip_dst;
  dst.sin_family = AF_INET;
  if (sendto(sock_fd, buffer, ip_to->ip_len, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
    perror("sendto() error");
    exit(EXIT_FAILURE);
    }
}


/*****
 *
 * send_tcp_ack
 *
 * In response to an incoming FIN, echo back an ACK
 */

void    
send_tcp_ack(u_char *in_reply_to)
{
  char buffer[PCKT_LEN] ;
  struct ip_hdr *ip_from;                /* the IP headers */ 
  struct ip_hdr *ip_to;
  struct tcp_hdr *tcp_from;              /* The TCP header */
  struct tcp_hdr *tcp_to;
  struct sockaddr_in dst;
  int size_ip ;
  u_char *op ;

  /* zero out the buffer space */
  memset(buffer,0,PCKT_LEN) ;

  ip_from = (struct ip_hdr *) in_reply_to ;
  ip_to = (struct ip_hdr *) buffer ;

  ip_to->ip_vhl = ip_from->ip_vhl ;
  ip_to->ip_tos = ip_from->ip_tos ;
  ip_to->ip_len = sizeof(struct ip_hdr) + sizeof(struct tcp_hdr) ;
  ip_to->ip_id = htons((u_short) (time(0) & 65535)) ;
  ip_to->ip_off = IP_DF ;
  ip_to->ip_ttl = 255 ;
  ip_to->ip_p = 6 ;
  ip_to->ip_sum = 0 ;
  ip_to->ip_src.s_addr = ip_from->ip_dst.s_addr  ;
  ip_to->ip_dst.s_addr = ip_from->ip_src.s_addr  ;

  op = in_reply_to;
  size_ip = IP_HL(ip_from)*4;
  op += size_ip ;
  tcp_from = (struct tcp_hdr *) op;

  op = buffer;
  size_ip = IP_HL(ip_to)*4;
  op += size_ip ;
  tcp_to = (struct tcp_hdr *) op ;

  tcp_to->th_sport = tcp_from->th_dport ;
  tcp_to->th_dport = tcp_from->th_sport ;
  tcp_to->th_seq = htonl(ntohl(tcp_from->th_ack) - 1);
  tcp_to->th_ack = htonl(ntohl(tcp_from->th_seq) + 1) ;
  tcp_to->th_offx2 = (5 << 4);  
  tcp_to->th_flags = (TH_ACK) ;
  tcp_to->th_win = htons(65535) ;
  tcp_to->th_sum = 0 ;
  tcp_to->th_urg = 0 ;

  /* IP checksum calculation */
  tcp_to->th_sum = htons(tcp_crc((u_char *) tcp_to, sizeof(struct tcp_hdr), 0, (uint32_t *) &(ip_to->ip_src.s_addr), (u_int32_t *) &(ip_to->ip_dst.s_addr))) ;

  ip_to->ip_sum = htons(ip_crc((unsigned short *) buffer, 10)) ;

  dst.sin_addr = ip_to->ip_dst;
  dst.sin_family = AF_INET;
  if (sendto(sock_fd, buffer, ip_to->ip_len, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
    perror("sendto() error");
    exit(EXIT_FAILURE);
    }
}


/*****
 *
 * server_request
 *
 * In response to an incoming request:
 *   ack the request (intended to stop the remote end timing out and retransmitting the request)
 *   generate an equivalent UDP request
 *   send the equivalent request to the back end server via UDP and collect the response
 *   repackage the date into 512 byte chunks
 *   sned the response back as a stream of packets
 *   and close with a FIN packet
 */

void
server_request(u_char *in_reply_to, char *s, int data_size) {
  char query[2048] ;
  char *qp ;
  int sockfd ;
  int portno = BACK_PORTNO ;
  char *hostname = BACK_HOST ;
  struct sockaddr_in serveraddr ;
  struct hostent *server ;
  int n ;
  char rbuffer[BUFSIZE+2] ;
  char *buf ;
  char *resp ;
  int ql ;
  int rsize ;
  char buffer[PCKT_LEN] ;
  struct ip_hdr *ip_from;                /* the IP headers */ 
  struct ip_hdr *ip_to;
  struct tcp_hdr *tcp_from;              /* The TCP header */
  struct tcp_hdr *tcp_to;
  struct sockaddr_in dst;
  int size_ip ;
  u_char *op ;
  u_short *length ;
  int tcp_sequence ;

  /* send an ACK to try and stop the other end retransmitting the request */
  /* stateless TCP can't detect duplicates (no remembered state!) */
  ip_from = (struct ip_hdr *) in_reply_to ;
  ip_to = (struct ip_hdr *) buffer ;

  ip_to->ip_vhl = ip_from->ip_vhl ;
  ip_to->ip_tos = ip_from->ip_tos ;
  ip_to->ip_id = htons((u_short) (time(0) & 65535)) ;
  ip_to->ip_off = IP_DF ;
  ip_to->ip_ttl = 255 ;
  ip_to->ip_p = 6 ;
  ip_to->ip_sum = 0 ;
  ip_to->ip_src.s_addr = ip_from->ip_dst.s_addr  ;
  ip_to->ip_dst.s_addr = ip_from->ip_src.s_addr  ;

  op = in_reply_to;
  size_ip = IP_HL(ip_from)*4;
  op += size_ip ;
  tcp_from = (struct tcp_hdr *) op;

  op = buffer;
  size_ip = IP_HL(ip_to)*4;
  op += size_ip ;
  tcp_to = (struct tcp_hdr *) op ;

  op += 20 ;

  tcp_to->th_sport = tcp_from->th_dport ;
  tcp_to->th_dport = tcp_from->th_sport ;
  tcp_to->th_ack = htonl(ntohl(tcp_from->th_seq) + data_size) ;
  tcp_to->th_offx2 = (5 << 4);  
  tcp_to->th_flags = TH_ACK ;
  tcp_to->th_win = htons(65535) ;
  tcp_to->th_sum = 0 ;
  tcp_to->th_urg = 0 ;

  tcp_sequence = ntohl(tcp_from->th_ack) ;

  ip_to->ip_len = sizeof(struct ip_hdr) + sizeof(struct tcp_hdr) ;
  tcp_to->th_seq = htonl(tcp_sequence);

  tcp_to->th_sum = htons(tcp_crc((u_char *) tcp_to, sizeof(struct tcp_hdr), 0, (uint32_t *) &(ip_to->ip_src.s_addr), (u_int32_t *) &(ip_to->ip_dst.s_addr))) ;

  ip_to->ip_sum = htons(ip_crc((unsigned short *) buffer, 10)) ;

  dst.sin_addr = ip_to->ip_dst;
  dst.sin_family = AF_INET;
  if (sendto(sock_fd, buffer, ip_to->ip_len, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
    perror("sendto() error");
    exit(EXIT_FAILURE);
    }


  /* we are going to write this to a UDP socket - the length of the query is the first
     two bytes of the TCP query, so we'll strip that off before translating that into 
     a UDP query, as DNS via UDP does not use an explicit length field in the payload*/ 
  s += 2 ;
  data_size -= 2 ;
  bcopy(s,query,data_size) ;


  /* send the modified query to slave DNS */
  if ((sockfd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("TCP slave socket() error") ;
    exit(EXIT_FAILURE) ;
    }

  if ((server = gethostbyname(hostname)) == NULL) {
    fprintf(stderr,"ERROR, no such host as %s\n",hostname) ;
    exit(EXIT_FAILURE) ;
    }

  /* build the server's Internet address */
  bzero((char *) &serveraddr, sizeof(serveraddr));

  serveraddr.sin_family = AF_INET;
  bcopy((char *)server->h_addr, (char *)&serveraddr.sin_addr.s_addr, server->h_length);
  serveraddr.sin_port = htons(portno);

  /* connect: create a connection with the server */
  if (connect(sockfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0) {
    perror("TCP connect error") ;
    exit(EXIT_FAILURE) ;
    }

  /* send the message line to the server */
  if ((n = write(sockfd, query, data_size)) < 0) {
    perror("ERROR writing to socket");
    exit(EXIT_FAILURE) ;
    }

  /* print the server's reply */
  length = (u_short *) rbuffer ;
  buf = &rbuffer[2] ;
  qp = resp = (char *) malloc(rsize = (BUFSIZE + 2)) ;
  ql = 0 ;
  qp[ql] = '\0';
  bzero(buf, BUFSIZE);
  if ((n = read(sockfd, buf, BUFSIZE - 1)) > 0) {
    buf[n] = '\0';

    /* write the length of the response at the start of the buffer */
    *length = htons(n) ;

    n += 2 ;

    if ((ql + n) > rsize) {
      char *tmp ;
      rsize += (BUFSIZE + 2) ;
      tmp = (char *) malloc(rsize) ;
      bcopy(resp,tmp,ql) ;
      free(resp) ;
      resp = tmp ;
      qp = &resp[ql] ;
      *qp = '\0';
      }
    bcopy(rbuffer,qp,n) ;
    qp[n] = '\0';
    qp += n ;
    ql += n ;
    bzero(buf, BUFSIZE) ;
    }
  if (n < 0) {
    perror("ERROR reading from socket");
    exit(EXIT_FAILURE) ;
    }
  close(sockfd);

  qp = resp ;
  while (ql >= 0) {
    if (ql < RESPSIZE) { rsize = ql ; }
    else { rsize = RESPSIZE; }
    bzero(op, RESPSIZE+1);
    bcopy(qp,op,rsize) ;
    op[rsize] = '\0';

    ip_to->ip_len = sizeof(struct ip_hdr) + sizeof(struct tcp_hdr) + rsize;
    tcp_to->th_seq = htonl(tcp_sequence);

    if (!ql) {
      tcp_to->th_flags = TH_ACK | TH_FIN;
      ql = -1 ;
      }

    tcp_to->th_sum = 0 ;
    /* IP checksum calculation */
    tcp_to->th_sum = htons(tcp_crc((u_char *) tcp_to, sizeof(struct tcp_hdr) + rsize, rsize, (uint32_t *) &(ip_to->ip_src.s_addr), (u_int32_t *) &(ip_to->ip_dst.s_addr))) ;

    ip_to->ip_sum = htons(ip_crc((unsigned short *) buffer, 10)) ;
    dst.sin_addr = ip_to->ip_dst;
    dst.sin_family = AF_INET;
    if (sendto(sock_fd, buffer, ip_to->ip_len, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
      perror("sendto() error");
      exit(EXIT_FAILURE);
      }

    ql -= rsize ;
    qp += rsize ;
    tcp_sequence += rsize ;
    }    
  free(resp) ;    
}


/*
 * packet dispatcher
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  struct ip_hdr *ip;                  /* The IP header */
  struct tcp_hdr *tcp;                /* The TCP header */
  char *ip_payload;                   /* The IP Packet */
  char *payload;                      /* Packet payload */

  int size_ip;
  int size_tcp;
  int size_payload;

  char cmd_buffer[2048] ;
	
	
  /* define IP header from Etherframe */
  ip = (struct ip_hdr*)(packet + SIZE_ETHERNET);
  size_ip = IP_HL(ip)*4;
  if (size_ip < 20) {
    printf("   * Invalid IP header length: %u bytes\n", size_ip);
    return;
    }
  if (ip->ip_p != IPPROTO_TCP) 
    return ;	

	
  /*
   *  OK, this packet is TCP.
   */

  	
  /* define/compute tcp header offset */
  tcp = (struct tcp_hdr*)(packet + SIZE_ETHERNET + size_ip);
  size_tcp = TH_OFF(tcp)*4;
  if (size_tcp < 20) {
    printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
    return;
    }

  if (ntohs(tcp->th_dport) != PORT)
    return ;


  /* define/compute tcp payload (segment) offset */
  ip_payload = (u_char *)(packet + SIZE_ETHERNET);
  payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
  /* compute tcp payload (segment) size */
  size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

  /* if this is a SYN packet then flick back a SYN + ACK */
  if (tcp->th_flags & TH_SYN) {
    send_tcp_synack(ip_payload) ;
    return ;
    }

  /* if this is a FIN packet then flick back a FIN + ACK */
  if (tcp->th_flags & TH_FIN) {
    send_tcp_ack(ip_payload) ;
    return ;
    }

  /* This is a data packet */
  if (size_payload > 0) {
    bcopy(payload,cmd_buffer,size_payload) ;
    cmd_buffer[size_payload] = '\0';
    server_request(ip_payload,cmd_buffer,size_payload) ;
    }
  return;
  }



int main(int argc, char **argv) 
{
  char *dev = NULL;                      /* capture device name */
  char errbuff[PCAP_ERRBUF_SIZE];        /* error buffer */
  pcap_t *handle ;                       /* packet capture handle */

  char filter_exp[1024];                /* The filter expression */	 
  struct bpf_program fp;		/* The compiled filter expression */	 
  bpf_u_int32 mask;		        /* The netmask of our sniffing device */
  bpf_u_int32 net;		        /* The IP of our sniffing device */
  struct in_addr *in ;


  sprintf(filter_exp,"dst port %d and dst host %s",PORT,THIS_HOST) ;

  
  /* check for capture device name on command-line */
  if (argc == 2) {
    dev = argv[1];
  }
  else if (argc > 2) {
    fprintf(stderr, "error: unrecognized command-line options\n\n");
    exit(EXIT_FAILURE);
    }
  else {
    /* find a capture device if not specified on command-line */
    dev = pcap_lookupdev(errbuff);
    if (dev == NULL) {
      fprintf(stderr, "Couldn't find default device: %s\n",errbuff);
      exit(EXIT_FAILURE);
    }
  }
	
  /* get network number and mask associated with capture device */
  if (pcap_lookupnet(dev, &net, &mask, errbuff) == -1) {
    fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuff);
    net = 0;
    mask = 0;
    }

  /* print capture info */
  in = (struct in_addr *) &net ;
  printf("Device: %s Network: %s Mask: %x\n", dev,inet_ntoa(*in),ntohl(mask));
  printf("Filter expression: %s\n", filter_exp);

  /* open capture device */  
  handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuff);	 
  if (handle == NULL) {		 
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuff);
    exit(EXIT_FAILURE) ;
    }	 

  /* compile the filter expression */
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {		 
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE) ;
    }	 

  if (pcap_setfilter(handle, &fp) == -1) {		 
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE) ;
    }

  /* open the raw socket */
  open_raw_socket() ;

  /* set up the packet cpature in an infinite loop */
  pcap_loop(handle, -1, got_packet, NULL) ;

  /* And close the session (not executed)*/
  pcap_close(handle);
  return(0);
}