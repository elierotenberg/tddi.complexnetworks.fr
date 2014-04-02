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
#include <sys/types.h>

#define __FAVOR_BSD 1
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>

#define PACKET_SIZE 1024
#define MESSAGE_SIZE 1024


typedef unsigned int uint32;
typedef unsigned short uint16;
typedef unsigned char uint8;
typedef unsigned char byte;

int verbose; // = 1 if verbose mode is on, = 0 else

typedef struct {             // probe_desc
  int udp_sock;              // UDP socket, used to send the UDP probe
  int icmp_sock;             // ICMP socket, used to receive the ICMP response
  int port;                  // UDP destination port
  uint8_t ttl;               // IP TTL
  char msg[MESSAGE_SIZE];    // UDP message
  struct timespec timeout_t; // Probe timeout in struct timespec format (delay after which a probe is considered lost)
} probe_desc;                // UDP probe descriptor typedef

typedef enum {
  TTL_EXPIRED,          // IP packet TTL expired. r_addr: ip (interface) used by the host to send the ICMP TIME EXCEEDED message
  TIMEOUT,              // No response has been received before the specified timeout has expired. r_addr: "*"
} response_type;

typedef struct {
  response_type r_type;
  char r_addr[INET_ADDRSTRLEN+1]; // if r_type == TTL_EXPIRED, contains the numbers-and-dots of the IPv4 interface that sent the TTL expired message. else, contains "*".
} probe_response;

#define NO_ICMP_PACKET_TO_READ 0
int icmp_packet_to_read = NO_ICMP_PACKET_TO_READ; // Global variable used by the handler to check whether there are ICMP packets to read.


int send_udp_probe(probe_desc* p_probe_desc, char* target) { // Send an UDP probe as described towards the target
  int udp_sock = p_probe_desc->udp_sock;
  int port = p_probe_desc->port;
  int ttl = p_probe_desc->ttl;
  const char* msg = p_probe_desc->msg;
  struct sockaddr_in target_addr;                                // Target adress representation
  char packet[PACKET_SIZE];                                      // Packet buffer allocation
  struct ip *iph = (struct ip*)packet;                           // IP header allocation
  struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct ip)); // UDP header allocation
  memset((char*)&target_addr, 0, sizeof(target_addr));           // Initialize all bits of target_addr to 0
  memset((char*)packet, 0, PACKET_SIZE);                         // Initialize all bits of packet to 0

  target_addr.sin_family = AF_INET;                              // Target address family: Internet
  target_addr.sin_port = htons(port);                            // Target port (passed argument) reformatted in big-endian binary format

  assert(inet_aton(target, &target_addr.sin_addr)!=0);                                       // converts the dots-and-number string target to a sin_addr and stores the result in target_addr.sin_addr
  assert(connect(udp_sock, (struct sockaddr*)&target_addr, sizeof(struct sockaddr_in))!=-1); // connects the socket (passed argument) to the target

  iph->ip_hl  = sizeof(struct ip) >> 2;                                        // IP header length: 5 bytes (default)
  iph->ip_v   = 0x4;                                                           // IP version: 4 (IPv4)
  iph->ip_len = sizeof(struct ip) + sizeof(struct udphdr) + strlen(msg) + 1;   // IP packet total length (IP datagram + UDP header + message)
  iph->ip_tos = 0;                                                             // IP Type Of Service: 0 (default)
  iph->ip_ttl = ttl;                                                           // IP TTL: ttl (passed argument)
  iph->ip_off = 0;                                                             // IP fragment offset: 0 (monofragment datagram)
  iph->ip_p   = IPPROTO_UDP;                                                   // IP transport layer protocol: UDP (17)
  iph->ip_sum = 0;                                                             // IP checksum: 0. Will be accurately set upon sending.
  iph->ip_src.s_addr = 0;                                                      // IP source address: 0. (Not to be used)
  iph->ip_dst.s_addr = target_addr.sin_addr.s_addr;                            // IP target address: target (passed argument), previously properly formatted


 /* store information to recognise answer packets */
  iph->ip_id = *(uint16 *)(&(iph->ip_dst.s_addr));                             // Stores the first 2 bytes of the target destination in the IP ID field, for subsequent recognition
  udph->uh_sport = htons(port);
  udph->uh_dport = target_addr.sin_port;                                       // UDP destination port: port (global variable)
  udph->uh_ulen = htons(sizeof(struct udphdr) + (strlen(msg)+1)*sizeof(char)); // UDP length (NS form)
  udph->uh_sum = 0;                                                            // UDP checksum: 0. (Not to be used)

  strcpy(packet+sizeof(struct ip)+sizeof(struct udphdr),msg); // Copies the message msg (global variable) into the correct location within the packet (packet starting address + ip header offset + udp header offset)

  return(write(udp_sock,packet,iph->ip_len)); // Finally tries to send the complete packet on the socket (passed argument)
}

void handler_trigger(int signalType) { // Signal handler that set icmp_packet_to_read to SIGIO whenever there is an icmp packet to read
  icmp_packet_to_read = signalType;
}

int inspect_icmp_packet(probe_desc* p_probe_desc, probe_response* p_probe_response) {
  int icmp_sock = p_probe_desc->icmp_sock;
  struct sockaddr_in r_addr;
  struct ip *r_iph, *s_iph;
  struct icmphdr *r_icmph;
  struct udphdr *s_udph;
  socklen_t len;
  int type;
  // int code;
  ssize_t r_size;
  char packet[PACKET_SIZE];
  if(verbose) {
    fprintf(stderr, "Inspecting ICMP Packet.\n");
  }
  len = (socklen_t)sizeof(r_addr);
  r_size = recvfrom(icmp_sock, (void *)packet, PACKET_SIZE, 0, (struct sockaddr *)&r_addr, &len);  // Attemps to read on the icmp socket buffer
  if (r_size <= 0) { // Actually no packet to read, false alert.
    return 0;
  }
  if(r_size < (int)(sizeof(struct ip) + sizeof(struct icmphdr) + sizeof(struct ip) + 8)) { // Packet is to small.
    return 0;
  }
  r_iph = (struct ip *)packet; // IP header of the received packet
  assert(r_iph->ip_p == IPPROTO_ICMP); // Checks that the packet is actually an ICMP packet
  r_icmph = (struct icmphdr *)((char *)r_iph+(r_iph->ip_hl*4)); // ICMP header of the received packet
  type = r_icmph->type; // Type of the ICMP message
  //  code = r_icmph->code; // Code of the ICMP message
  if(type != ICMP_TIME_EXCEEDED) { // Message type is not ICMP_TIME_EXCEEDED, and is therefore irrelevant.
    return 0;
  }
  s_iph = (struct ip *)((char *)r_icmph+sizeof(struct icmphdr)); // Original IP header attached to the ICMP error message
  s_udph = (struct udphdr *)((char *)s_iph+(s_iph->ip_hl*4));    // Original UDP header attached to the ICMP error message
  //    if (verbose) fprintf(stderr," from %s",inet_ntoa(r_iph->ip_src));
  //    if (verbose) fprintf(stderr,", initially %s. ",inet_ntoa(s_iph->ip_dst));
  if( s_udph->uh_dport != htons(p_probe_desc->port) ) { // Original UDP destination port doesn't match
    return 0;
  }
  if( s_udph->uh_sport != htons(p_probe_desc->port) ) { // Inconsistent packet (UDP source port first check)
    return 0;
  }
  if ( *(uint16 *)(&(s_iph->ip_dst)) != s_iph->ip_id ) { // Inconsistent packet (IP id second check)
    return 0;
  }
  // At this point, the packet is indeed a TTL-expired message sent by a host encounter along the way towards the target.
  p_probe_response->r_type = TTL_EXPIRED;
  sprintf(p_probe_response->r_addr, "%s", inet_ntoa(r_iph->ip_src));
  return 1;
}

void recv_udp_response(probe_desc* p_probe_desc, probe_response* p_probe_resp) {
  struct timespec req, rem;
  req.tv_sec = p_probe_desc->timeout_t.tv_sec;
  req.tv_nsec = p_probe_desc->timeout_t.tv_nsec;
  while(icmp_packet_to_read != NO_ICMP_PACKET_TO_READ) {
    if(verbose) {
      fprintf(stderr, "Signal interruption (%d).\n", icmp_packet_to_read);
    }
    if(icmp_packet_to_read == SIGIO) {
      icmp_packet_to_read = NO_ICMP_PACKET_TO_READ;
      if(inspect_icmp_packet(p_probe_desc, p_probe_resp)) {
    return;
      }
    }
    else {
      icmp_packet_to_read = NO_ICMP_PACKET_TO_READ;
    }
  }
  while(nanosleep(&req, &rem) != 0) { // Reads any incoming ICMP packets in search for a proper response until timeout expires
    if(verbose) {
      fprintf(stderr, "Nanosleep interrupted. (SIGIO=%d, icmp_packet_to_read=%d)\n", SIGIO, icmp_packet_to_read);
    }
    while(icmp_packet_to_read != NO_ICMP_PACKET_TO_READ) {
      if(verbose) {
    fprintf(stderr, "Signal interruption (%d).\n", icmp_packet_to_read);
      }
      if(icmp_packet_to_read == SIGIO) {
    icmp_packet_to_read = NO_ICMP_PACKET_TO_READ;
    if(inspect_icmp_packet(p_probe_desc, p_probe_resp)) {
      do {
        req.tv_sec = rem.tv_sec;
        req.tv_nsec = rem.tv_nsec;
      } while(nanosleep(&req, &rem) != 0);
      return;
    }
      }
      else {
    icmp_packet_to_read = NO_ICMP_PACKET_TO_READ;
      }
    }
    req.tv_sec = rem.tv_sec;
    req.tv_nsec = rem.tv_nsec;
    if(verbose) {
      fprintf(stderr, "Returning to nanosleep (sec = %d, nsec = %d)\n", (int)req.tv_sec, (int)req.tv_nsec);
    }
  }
  p_probe_resp->r_type = TIMEOUT;
  sprintf(p_probe_resp->r_addr, "*");
}

inline int is_valid(byte* ip) { // Checks whether an IP is valid for probing. Includes blacklisting.

  if(ip[0]==0)
    return 0;
  if(ip[0]==10)
    return 0;
  if(ip[0]==14)
    return 0;
  if(ip[0]==39)
    return 0;
  if(ip[0]==127)
    return 0;
  if((ip[0]==128) && (ip[1]==0))
    return 0;
  if((ip[0]==169) && (ip[1]==254))
    return 0;
  if((ip[0]==172) && (ip[1]>=16) && (ip[1]<=31))
    return 0;
  if((ip[0]==191) && (ip[1]==255))
    return 0;
  if((ip[0]==192) && (ip[1]==0) && (ip[2]==0))
    return 0;
  if((ip[0]==192) && (ip[1]==0) && (ip[2]==2))
    return 0;
  if((ip[0]==192) && (ip[1]==88) && (ip[2]==99))
    return 0;
  if((ip[0]==192) && (ip[1]==168))
    return 0;
  if((ip[0]==192) && ((ip[1]==18) || (ip[1]==19)))
    return 0;
  if((ip[0]==223) && (ip[1]==255) && (ip[2]==255))
    return 0;
  if(ip[0]>=224)
    /* Corresponds to multicast (former class D networks), */
    /* first octet between 224 and 239, */
    /* and reserved (former class E networks), */
    /* first octet between 240 and 255 */
    return 0;
  if(ip[3]==255)
    return 0;
  if(ip[3]==0)
    return 0;

  // PlanetLab blacklist below
  if(ip[0] == 63 && ip[1] == 215 && ip[2] >= 104 && ip[2] <= 107)
    return 0;
  if(ip[0] == 67 && ip[1] == 210 && ip[2] >= 80 && ip[2] <= 95)
    return 0;
  if(ip[0] == 74 && ip[1] == 202 && ip[2] >= 16 && ip[2] <= 19)
    return 0;
  if(ip[0] == 207 && ip[1] == 174 && ip[2] == 77)
    return 0;
  if(ip[0] == 207 && ip[1] == 174 && ip[2] == 98)
    return 0;
  if(ip[0] == 207 && ip[1] == 174 && ip[2] == 114)
    return 0;
  if(ip[0] == 207 && ip[1] == 174 && ip[2] == 173)
    return 0;
  if(ip[0] == 207 && ip[1] == 174 && ip[2] == 210)
    return 0;
  if(ip[0] == 207 && ip[1] == 174 && ip[2] == 211)
    return 0;
  if(ip[0] == 63 && ip[1] == 214 && ip[2] >= 32 && ip[2] <= 39)
    return 0;
  if(ip[0] == 63 && ip[1] == 215 && ip[2] >= 108 && ip[2] <= 111)
    return 0;
  if(ip[0] == 64 && ip[1] == 74 && ip[2] == 187)
    return 0;
  if(ip[0] == 199 && ip[1] == 45 && (ip[2] == 166 || ip[2] == 240))
    return 0;

  return 1;
}

inline void usage(char* cmd) {
  fprintf(stderr, "%s sends a UDP probes towards random valid IP addresses with increasing TTL (starting from 0), until more than one host sends back an ICMP Time Exceeded message, and displays the observed interfaces for each TTL.\n", cmd);
  fprintf(stderr, "Output format: <TTL> <i> <Addres of i-th target> <Response for i-th target (\"*\" if no response)>\n");
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, " %s [-p port] [-n number] [-d delay] [-t timeout] [-m message] [-T max_ttl] [-v] [-h]\n", cmd);
  fprintf(stderr, "   -p port: UDP Destination port. Default: Random port in the 49152-65535 range.\n");
  fprintf(stderr, "   -n number: Number of probes sent for each TTL. Default: 100.\n");
  fprintf(stderr, "   -d delay: Delay (in milliseconds) between the sending of two successive probes. Default: 1000.\n");
  fprintf(stderr, "   -t timeout: Timeout (in milliseconds) before a probe is declared lost. Default: 1000.\n");
  fprintf(stderr, "   -m message: Content of the UDP message Default: admin@localhost.\n");
  fprintf(stderr, "   -T max_ttl: Stop after at most TTL, regardless of whether more than one host sent back an ICMP Time Exceeded message. Default: 30.\n");
  fprintf(stderr, "   -v: Verbose mode. (Default: not verbose)\n");
  fprintf(stderr, "   -h: Displays this help.\n");
}

inline void ms_to_timespec(int timeout_ms, struct timespec* p_timeout_t) { // Converts the given timeout in millisec into the corresponding timespec
  p_timeout_t->tv_sec = timeout_ms/1000;                 // seconds = milliseconds / 1000
  p_timeout_t->tv_nsec = (timeout_ms % 1000)*1000000;    // nanoseconds = (milliseconds % 1000) * 1000000
}

inline void pickTarget(char* target)
{
  byte ip[4];
  int k;
  do {
    for(k = 0; k < 4; k++)
      ip[k] = rand() % 256;
  } while(!is_valid(ip));
  sprintf(target, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
}

int main(int argc, char *argv[])
{
  int port;
  int number;
  int delay_ms;
  int timeout_ms;
  char msg[MESSAGE_SIZE];
  int max_ttl;
  char c;
  int udp_sock, icmp_sock;
  struct sigaction sig_handler;
  int flags;
  icmp_packet_to_read = NO_ICMP_PACKET_TO_READ;

  assert((sizeof(uint8)==1) && (sizeof(uint16)==2) && (sizeof(uint32)==4));

  srand(getpid());

  // Inits the parameters with default values

  port = 49152 + random() %(65535-49152);
  number = 100;
  timeout_ms = 1000;
  delay_ms = 1000;
  verbose = 0;
  sprintf(msg, "admin@localhost");
  max_ttl = 30;

  while ((c=getopt(argc,argv,"hvp:n:d:t:m:T:"))!=-1)
    switch(c) {
    case 'p':
      port = atoi(optarg);
      break;
    case 'n':
      number = atoi(optarg);
      break;
    case 'd':
      delay_ms = atoi(optarg);
      break;
    case 't':
      timeout_ms = atoi(optarg);
      break;
    case 'm' :
      sprintf(msg, "%s", optarg);
      break;
    case 'T' :
      max_ttl = atoi(optarg);
      break;
    case 'v':
      verbose = 1;
      break;
    case 'h':
      usage(argv[0]);
      exit(0);
      break;
    default:
      fprintf(stderr, "Invalid parameters.\n");
      usage(argv[0]);
      exit(0);
      break;
    }

  if(verbose) {
    fprintf(stderr, "Port: %d\n", port);
    fprintf(stderr, "Number of probes per TTL: %d\n", number);
    fprintf(stderr, "Maximum TTL: %d\n", max_ttl);
    fprintf(stderr, "Delay between probes: %d ms\n", delay_ms);
    fprintf(stderr, "Probe timeout: %d ms\n", timeout_ms);
    fprintf(stderr, "Content of the UDP message: %s (message size: %d)\n", msg, (int)strlen(msg));
  }


  int one = 1;
  assert((udp_sock=socket(PF_INET,SOCK_RAW,IPPROTO_RAW))!=-1);             // Prepares the udp socket
  assert(setsockopt(udp_sock,IPPROTO_IP,IP_HDRINCL,&one,sizeof(one))!=-1);
  assert((icmp_sock=socket(AF_INET, SOCK_RAW, IPPROTO_ICMP))!=-1);         // Prepares the icmp socket


  assert(setuid(getuid())==0);   // Checks for root privileges
  assert(icmp_sock>0);

  sig_handler.sa_handler = handler_trigger; // Sets the signal handler for SIGIO
  assert(sigemptyset(&sig_handler.sa_mask)>=0); // Creates a mask that mask no signal

  sig_handler.sa_flags = 0; // No flags
  assert(sigaction(SIGIO,&sig_handler,NULL)>=0);

  assert(fcntl(icmp_sock,F_SETOWN,getpid())>=0); // Own the socket to receive the SIGIO message

  /* Arrange for nonblocking I/O and SIGIO delivery */
  assert((flags = fcntl(icmp_sock, F_GETFL, 0))>=0);
  assert(fcntl(icmp_sock,F_SETFL,(flags|O_NONBLOCK)|FASYNC)>=0);
  // assert((flags = fcntl(udp_sock, F_GETFL, 0))>=0);
  // assert(fcntl(udp_sock,F_SETFL,(flags|O_NONBLOCK)|FASYNC)>=0);

  // PlanetLab-specific trick to ensure proper ICMP response forwarding.

  struct sockaddr_in sin;
  int dummy_sock;
  assert((dummy_sock=socket(AF_INET, SOCK_DGRAM, 0))!=-1); // Prepares the dummy socket

  bzero((char*)&sin, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons(port);
  assert(bind(dummy_sock, (struct sockaddr *)& sin, sizeof(sin)) != -1);

  // End of the PlanetLab-specific trick.


  int current_ttl = 0;
  int number_of_responses = 0;
  char **responses;
  if(verbose) {
    fprintf(stderr, "Entering the TTL loop.\n");
  }
  while(number_of_responses <= 2 && current_ttl < max_ttl) { // Main loop over the ttl.
    if(verbose) {
      fprintf(stderr, "TTL = %d\n", current_ttl);
    }
    responses = (char**)malloc(sizeof(char*)*number);
    int iTarget;
    int iResponse;
    current_ttl++;
    number_of_responses = 0;
    if(verbose) {
      fprintf(stderr, "Entering the target loop.\n");
    }
    for(iTarget = 0; iTarget < number; iTarget++) { // Loop over the targets
      char curTarget[INET_ADDRSTRLEN+1];
      probe_desc probe_d;
      probe_response probe_r;
      int try_counter = 0;
      int already_known = 0;
      pickTarget(curTarget);  // Picks a random, valid IP address as a target
      /* Prepare the probe_desc struct to be passed to the send_udp_probe function */
      probe_d.udp_sock = udp_sock;
      probe_d.icmp_sock = icmp_sock;
      probe_d.port = port;
      probe_d.ttl = (uint8_t)current_ttl;
      sprintf(probe_d.msg, "%s", msg);
      ms_to_timespec(timeout_ms, &probe_d.timeout_t);

      if(verbose) {
    fprintf(stderr, "Sending probe: TTL=%d, target=%s\n", current_ttl, curTarget);
      }
      while(send_udp_probe(&probe_d, curTarget) <= 0) {   // Tries to send the UDP probe
    fprintf(stderr, "Sending attempt failed. (%d)\n", ++try_counter);
      };
      if(verbose) {
    fprintf(stderr, "Probe sent, waiting for responses.\n");
      }
      recv_udp_response(&probe_d, &probe_r); // Waits for a response (up to the specified timeout)
      if(probe_r.r_type == TTL_EXPIRED) {
    if(verbose) {
      fprintf(stderr, "TTL Expired: %s\n", probe_r.r_addr);
    }
    for(iResponse = 0; iResponse < number_of_responses; iResponse++) {
      if(strcmp(responses[iResponse], probe_r.r_addr) == 0) {
        already_known = 1;
        break;
      }
    }
    if(!already_known) {
      if(verbose) {
        fprintf(stderr, "New response: %s\n", probe_r.r_addr);
      }
      responses[number_of_responses] = (char*)malloc(sizeof(char)*INET_ADDRSTRLEN+1);
      sprintf(responses[number_of_responses], "%s", probe_r.r_addr);
      number_of_responses++;
    }
    else {
      if(verbose) {
        fprintf(stderr, "Response already known: %s.\n", probe_r.r_addr);
      }
    }
      }
      else {
    if(verbose) {
      fprintf(stderr, "Timeout (No response)\n");
    }
      }
      fprintf(stdout, "%d %d %s %s\n", current_ttl, iTarget, curTarget, probe_r.r_addr);
    }
    if(verbose) {
      fprintf(stderr, "Exiting the target loop, %d response(s) for TTL %d.\n", number_of_responses, current_ttl);
    }
    for(iResponse = 0; iResponse < number_of_responses; iResponse++) {
      free(responses[iResponse]);
    }
    free(responses);
  }

  if(verbose) {
    fprintf(stderr, "Exiting the TTL loop.\n");
  }


  return 0;
}