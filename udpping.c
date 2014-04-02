#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <time.h>
#include <math.h>
#include <assert.h>
#include <signal.h>
#include <fcntl.h>
#include <arpa/inet.h>

#define __FAVOR_BSD 1
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>

typedef unsigned int uint32;
typedef unsigned short uint16;
typedef unsigned char uint8;

/* initial sending ttl */
uint8 ttl = 255;

#define PACKET_SIZE 1000
#define STR_SIZE 1000
#define default_msg "UDP Ping"

char msg[STR_SIZE+1];

/* delay (in seconds) to wait after sending all packets (answers may still arrive) */
#define FINAL_DELAY 60

int source_port, target_port;
int verbose = 0;
int packet_to_read = 0;

/* blocking but may be interrupted by the arrival of an ICMP packet (or any signal) */
int send_udp_ping(int udp_sock, char *target){
 struct sockaddr_in target_addr;
 char packet[PACKET_SIZE];
 struct ip *iph = (struct ip *)packet;
 struct udphdr *udph = (struct udphdr *)(packet+sizeof(struct ip));
 int msglen = strlen(msg);

 memset((char *)&target_addr, 0, sizeof(target_addr));
 memset((char *)packet, 0, PACKET_SIZE);

 target_addr.sin_family = AF_INET;
 target_addr.sin_port = htons(target_port);
 assert(inet_aton(target, &target_addr.sin_addr)!=0);
 assert(connect(udp_sock, (struct sockaddr *)&target_addr, sizeof(struct sockaddr_in))!=-1);

 iph->ip_v = 0x4;
 iph->ip_hl = sizeof(struct ip) >> 2;
 iph->ip_tos = 0;
 iph->ip_len = sizeof(struct ip) + sizeof(struct udphdr) + msglen;
 iph->ip_ttl = ttl;
 iph->ip_off = 0;
 iph->ip_p = IPPROTO_UDP;
 iph->ip_sum = 0;
 iph->ip_src.s_addr = 0;
 iph->ip_dst.s_addr = target_addr.sin_addr.s_addr;

 /* store information to recognise answer packets */
 iph->ip_id = htons(*(uint16 *)(&(iph->ip_dst.s_addr)) ^ *(uint16 *)(((char *)&(iph->ip_dst.s_addr))+2));

 udph->uh_sport = htons(source_port);
 udph->uh_dport = target_addr.sin_port;
 udph->uh_ulen = htons((uint16)(sizeof(struct udphdr) + msglen));
 udph->uh_sum = 0;

 strcpy(packet+sizeof(struct ip)+sizeof(struct udphdr),msg);

 return(write(udp_sock,packet,iph->ip_len));
 }

/* do as little things as possible in a signal handler, *
 * in particular avoid function calls to printf etc     */
void Handler(int signalType){
 packet_to_read = signalType;
 }

typedef unsigned char byte;

inline long long_from_ints(long ip0, long ip1, long ip2, long ip3) {
  return ip0*256*256*256 + ip1*256*256 + ip2*256 + ip3;
}

inline long long_from_bytep(byte *ip) {
  return long_from_ints(ip[0], ip[1], ip[2], ip[3]);
}


inline int in_interval(long i, long imin, long imax) {
  return (i >= imin && i <= imax);
}

int is_valid(byte *ip)
{
  if (ip[0]==0)
    return(0);
  if (ip[0]==10)
    return(0);
  if (ip[0]==14)
    return(0);
  if (ip[0]==39)
    return(0);
  if (ip[0]==127)
    return(0);
  if ((ip[0]==128) && (ip[1]==0))
    return(0);
  if ((ip[0]==169) && (ip[1]==254))
    return(0);
  if ((ip[0]==172) && (ip[1]>=16) && (ip[1]<=31))
    return(0);
  if ((ip[0]==191) && (ip[1]==255))
    return(0);
  if ((ip[0]==192) && (ip[1]==0) && (ip[2]==0))
    return(0);
  if ((ip[0]==192) && (ip[1]==0) && (ip[2]==2))
    return(0);
  if ((ip[0]==192) && (ip[1]==88) && (ip[2]==99))
    return(0);
  if ((ip[0]==192) && (ip[1]==168))
    return(0);
  if ((ip[0]==192) && ((ip[1]==18) || (ip[1]==19)))
    return(0);
  if ((ip[0]==223) && (ip[1]==255) && (ip[2]==255))
    return(0);
  if (ip[0]>=224)
    /* Corresponds to multicast (former class D networks), */
    /* first octet between 224 and 239, */
    /* and reserved (former class E networks), */
    /* first octet between 240 and 255 */
    return(0);
  if (ip[3]==255)
    return(0);
  if (ip[3]==0)
    return(0);

  // PlanetLab blacklist below

  long i = long_from_bytep(ip);
  if(in_interval(i, long_from_ints(63, 215, 104, 0), long_from_ints(63, 215, 107, 255)))
    return 0;
  if(in_interval(i, long_from_ints(67, 210, 80, 0), long_from_ints(67, 210, 95, 255)))
    return 0;
  if(in_interval(i, long_from_ints(74, 202, 16, 0), long_from_ints(74, 202, 19, 255)))
    return 0;
  if(in_interval(i, long_from_ints(207, 174, 77, 0), long_from_ints(207, 174, 77, 255)))
    return 0;
  if(in_interval(i, long_from_ints(207, 174, 98, 0), long_from_ints(207, 174, 98, 255)))
    return 0;
  if(in_interval(i, long_from_ints(207, 174, 114, 0), long_from_ints(207, 174, 114, 255)))
    return 0;
  if(in_interval(i, long_from_ints(207, 174, 173, 0), long_from_ints(207, 174, 173, 255)))
    return 0;
  if(in_interval(i, long_from_ints(207, 174, 210, 0), long_from_ints(207, 174, 211, 255)))
    return 0;
  if(in_interval(i, long_from_ints(63, 214, 32, 0), long_from_ints(63, 214, 39, 255)))
    return 0;
  if(in_interval(i, long_from_ints(63, 215, 108, 0), long_from_ints(63, 215, 111, 255)))
    return 0;
  if(in_interval(i, long_from_ints(64, 74, 187, 0), long_from_ints(64, 74, 187, 255)))
    return 0;
  if(in_interval(i, long_from_ints(199, 45, 166, 0), long_from_ints(199, 45, 166, 255)))
    return 0;
  if(in_interval(i, long_from_ints(199, 45, 240, 0), long_from_ints(199, 45, 240, 255)))
    return 0;

  return 1;
}

int get_packets(int icmp_sock){
  struct sockaddr_in r_addr;
  struct ip *r_iph, *s_iph;
  struct icmphdr *r_icmph;
  struct udphdr *s_udph;
  socklen_t len;
 int type, code;
 ssize_t r_size;
 int n = 0;
 char packet[PACKET_SIZE];
 do{
  len = (socklen_t)sizeof(r_addr);
  r_size = recvfrom(icmp_sock, (void *)packet, PACKET_SIZE, 0, (struct sockaddr *)&r_addr, &len);
  if (r_size>0){
   if (verbose) fprintf(stderr,"ICMP packet (%d bytes from %s).",(int)r_size,inet_ntoa(r_addr.sin_addr));
   else fprintf(stderr,"+");
   fflush(stderr);
   if (r_size < (int)(sizeof(struct ip) + sizeof(struct icmphdr) + sizeof(struct ip) + 8)){
    if (verbose) fprintf(stderr,"Packet too small.");
    }
   else{
    r_iph = (struct ip *)packet;
    assert(r_iph->ip_p==IPPROTO_ICMP);
    r_icmph = (struct icmphdr *)((char *)r_iph+(r_iph->ip_hl*4));
    type = r_icmph->type;
    code = r_icmph->code;
    switch (type){
     case ICMP_TIME_EXCEEDED:
      if (verbose) fprintf(stderr," ICMP_TIME_EXCEEDED\n");
      break;
     case ICMP_ECHOREPLY:
      if (verbose) fprintf(stderr," ICMP_ECHOREPLY\n");
      break;
     case ICMP_DEST_UNREACH:
      if (verbose) fprintf(stderr," ICMP_DEST_UNREACH ");
      if (code!=3){
       if (verbose) fprintf(stderr,"unknown code (%d).\n",code);
       break;
       }
      if (verbose) fprintf(stderr,"port unreachable");
      else fprintf(stderr,"*");
      s_iph = (struct ip *)((char *)r_icmph+sizeof(struct icmphdr));
      s_udph = (struct udphdr *)((char *)s_iph+(s_iph->ip_hl*4));
      if (verbose) fprintf(stderr," from %s",inet_ntoa(r_iph->ip_src));
      if (verbose) fprintf(stderr,", initially %s. ",inet_ntoa(s_iph->ip_dst));
      if (s_udph->uh_dport != htons(target_port)) {
       if (verbose) fprintf(stderr,"Packet not for us (invalid target port).\n");
       else fprintf(stderr,"-");
       break;
       }
      if (s_udph->uh_sport != htons(source_port)) {
       if (verbose) fprintf(stderr,"Packet not for us (invalid source port).\n");
       else fprintf(stderr,"-");
       break;
       }
      if ( ntohs(*(uint16 *)(&(s_iph->ip_dst)) ^ *(uint16 *)(((char *)&(s_iph->ip_dst.s_addr))+2)) != s_iph->ip_id ) {
       if (verbose) fprintf(stderr,"Inconsistent packet (IP id).\n");
       else fprintf(stderr,"-");
       break;
       }
      if (verbose) fprintf(stderr,"Packet is for us and consistent. Success.\n");
      fflush(stderr);
      fprintf(stdout,"%s",inet_ntoa(r_iph->ip_src));
      fprintf(stdout," %s\n",inet_ntoa(s_iph->ip_dst));
      fflush(stdout);
      n++;
      break;
     default:
      if (verbose) fprintf(stderr,"Unknown type.\n");
     }
    }
   }
  }while (r_size>0);
 return(n);
 }

void usage(char *cmde){
 fprintf(stderr, "%s reads IP addresses (text dotted representation, one address per line) on its standard input, and sends a UDP packet to them. It displays information (sender and coresponding target) on the corresponding ICMP port unreachable packets it receives.\n",cmde);
 fprintf(stderr, "Usage:\n");
 fprintf(stderr, " %s [-v] [-p port] [-d delay]\n", cmde);
 fprintf(stderr, " -v: verbose mode.\n -p port: target port (if unspecified, a random port is used).\n -d delay: number of milliseconds between two packets.\n -h: this help.\n");
 fprintf(stderr, "Warning: if delay is too small (machine dependent) the program may overflow the network.\n");
 exit(1);
 }

int main(int argc, char *argv[]){
 const int one = 1;
 struct sigaction handler;
 char c;
 unsigned long int n_try=0, n_sent=0, n_ok=0;
 int icmp_sock, udp_sock, foo_sock;
 char target[STR_SIZE];
 int linesize=STR_SIZE;
 char line[linesize];
 byte ip[4];
 int ipint[4];
 int lgr, i;
 int delay = 1000000; /* in microseconds */
 struct timespec req, rem;
 int flags;
 sprintf(msg, "%s", default_msg);

 source_port = 49152 + random() %(65535-49152);

 assert((sizeof(uint8)==1) && (sizeof(uint16)==2) && (sizeof(uint32)==4));
 srandom(getpid());
 assert(RAND_MAX>255);

 /* set up target port number (command-line argument or random) */
 target_port = 49152 + random() %(65535-49152);

 while ((c=getopt(argc,argv,"hvp:d:m:"))!=-1)
  switch(c){
   case 'v':
    verbose = 1;
    break;
   case 'p':
    target_port = atoi(optarg);
    break;
   case 'd':
    delay = atoi(optarg);
    break;
   case 'm':
    sprintf(msg, "%s", optarg);
    break;
   case 'h':
    usage(argv[0]);
    break;
   default:
    fprintf(stderr, "Invalid parameters. Use %s -h for help.",argv[0]);
    usage(argv[0]);
   }

 fprintf(stderr,"source port %d, target port %d, delay between packets %d ms\n",source_port,target_port,delay);

 /* Prepare sockets */
 assert((udp_sock=socket(PF_INET,SOCK_RAW,IPPROTO_RAW))!=-1);
 assert(setsockopt(udp_sock,IPPROTO_IP,IP_HDRINCL,&one,sizeof(one))!=-1);
 assert((icmp_sock=socket(AF_INET, SOCK_RAW, IPPROTO_ICMP))!=-1);
 /* discard root privileges */
 assert(setuid(getuid())==0);
 assert(icmp_sock>0);
 /* Set signal handler for SIGIO */
 handler.sa_handler = Handler;
 /* Create mask that mask no signal */
 assert(sigemptyset(&handler.sa_mask)>=0);
 /* No flags */
 handler.sa_flags = 0;
 assert(sigaction(SIGIO,&handler,NULL)>=0);
 /* We must own the socket to receive the SIGIO message */
 assert(fcntl(icmp_sock,F_SETOWN,getpid())>=0);
 /* Arrange for nonblocking I/O and SIGIO delivery */
 assert((flags = fcntl(icmp_sock, F_GETFL, 0))>=0);
 assert(fcntl(icmp_sock,F_SETFL,(flags|O_NONBLOCK)|FASYNC)>=0);

 /* for PlanetLab: bind source port */
 struct sockaddr_in sin;
 assert((foo_sock = socket(AF_INET, SOCK_DGRAM, 0)) >= 0);
 bzero((char *)& sin, sizeof(sin));
 sin.sin_family = AF_INET;
 sin.sin_port = htons(source_port);
 assert(bind(foo_sock,(struct sockaddr *)&sin,sizeof(sin))>=0);

 while (!feof(stdin)){
  while ((!feof(stdin)) && (fgets(line,STR_SIZE,stdin)!=line)){
   if (packet_to_read){
    packet_to_read = 0;
    n_ok += get_packets(icmp_sock);
    }
   }
  if (feof(stdin))
   break;

  /* get target address */
  assert(sscanf(line,"%d.%d.%d.%d\n",&(ipint[0]),&(ipint[1]),&(ipint[2]),&(ipint[3]))==4);
  for (i=0;i<4;i++)
   ip[i]=(byte)ipint[i];
  n_try++;
  lgr=snprintf(target,STR_SIZE,"%d.%d.%d.%d",ip[0],ip[1],ip[2],ip[3]);
  assert((lgr>0) && (lgr<STR_SIZE));
  if (verbose)
   fprintf(stderr,"UDP ping to %s\n",target);

  /* send UDP packet and get answers */
  if (is_valid(ip)){
   /* try sending until success, and manage answers */
   while (send_udp_ping(udp_sock,target)<=0){
    if (packet_to_read){
     packet_to_read = 0;
     n_ok += get_packets(icmp_sock);
     }
    }
   n_sent++;
   /* wait before sending next packet, but manage arrivals */
   req.tv_sec = (int)delay/1000000;
   req.tv_nsec = (delay%1000000)*1000;
   while (nanosleep(&req,&rem)==-1){
    /* check if there are packets to read */
    if (packet_to_read){
     packet_to_read = 0;
     n_ok += get_packets(icmp_sock);
     }
    req.tv_sec = rem.tv_sec;
    req.tv_nsec = rem.tv_nsec;
    }
   if (packet_to_read){
    packet_to_read = 0;
    n_ok += get_packets(icmp_sock);
    }
   }
  else
   fprintf(stderr,"Invalid address: %d.%d.%d.%d\n",ip[0],ip[1],ip[2],ip[3]);

  /* print status */
  if (verbose){
   if (n_sent%10000==0) fprintf(stderr,"%ld UDP ping launched until now (%ld valid answers, %ld random IP sampled).\n",n_sent,n_ok,n_try);
   }
  else fprintf(stderr,".");
  fflush(stderr);

  } /* end of main loop */

 /* wait for last packets and manage them */
 if (verbose){
  fprintf(stderr,"END OF SENDING LOOP");
  fflush(stderr);
  }
 req.tv_sec = FINAL_DELAY;
 req.tv_nsec = 0;
 while (nanosleep(&req,&rem)==-1){
  if (packet_to_read){
   packet_to_read = 0;
   n_ok += get_packets(icmp_sock);
   }
  req.tv_sec = rem.tv_sec;
  req.tv_nsec = rem.tv_nsec;
  }

 close(udp_sock);
 close(icmp_sock);
 return 0;
 }
