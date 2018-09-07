#include <stdio.h> //printf
#include <string.h> //memset
#include <stdlib.h> //for exit(0);
#include <sys/socket.h>
#include <errno.h> //For errno - the error number
#include <thread>
#include <netdb.h> //hostend
#include <arpa/inet.h>
#include <netinet/udp.h>   // Provides declarations for udp header
#include <netinet/ip.h>    //Provides declarations for ip header
#include <unistd.h>
#include <vector>


// The packet length
#define PCKT_LEN 256

// https://www.binarytides.com/raw-udp-sockets-c-linux/
void error(const char *msg){
    perror(msg);
    exit(0);
}

// https://stackoverflow.com/questions/4888285/send-an-udp-packet-and-receive-an-icmp-response-from-router-in-c
void udp_scan(const char* dest_IP, const char* port) {
    // buffers to send/receive
    char datagram[PCKT_LEN], recv_buff[PCKT_LEN];
    memset(datagram, 0, PCKT_LEN); // fill buffer with zero
    memset(recv_buff, 0, PCKT_LEN); // fill buffer with zero
 
    int send_sock, recv_sock;     // sockets
    timeval ttl;    // time to live
    ttl.tv_sec = 5;
    ttl.tv_usec = 0;

    struct sockaddr_in dest_addr;

    send_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (send < 0) {
        error("ERROR! Unable to open socket");
    }

    recv_sock = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (recv_sock < 0) {
        error("ERROR! Unable to open socket");
    }

    // Define time to live
    if(setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, (timeval *)&ttl, sizeof(timeval)) != 0) {
        error("Could not process setsockopt");
    }

    // fill destination address fields
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(atoi(port));
    struct hostent *destination = gethostbyname(dest_IP);
    memcpy((char *)&dest_addr.sin_addr.s_addr,
           (char *)destination->h_addr,
           destination->h_length);
    
    //Send the packet
    if (sendto (send_sock, datagram, sizeof(datagram), 0, (struct sockaddr*) &dest_addr, sizeof (dest_addr)) < 0) {
        error("ERROR! Unable to send");
    }

    if(recvfrom(recv_sock, recv_buff, sizeof(recv_buff), 0, NULL, NULL) < 0 ) {
        printf("Port most likely open\n");
    } 
    else {
        printf ("ICMP reply\n");
    }

    close(send_sock);
    close(recv_sock);
}

int main(int argc, char *argv[]) {
    // error check
    if (argc < 3) {
       fprintf(stderr,"usage %s hostname port\n", argv[0]);
       exit(0);
    }


    udp_scan(argv[1], argv[2]);
    
    return 0;
}