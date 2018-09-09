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
#define PCKT_LEN 1024

// https://www.binarytides.com/raw-udp-sockets-c-linux/
void error(const char *msg){
    perror(msg);
    exit(0);
}

// https://stackoverflow.com/questions/4888285/send-an-udp-packet-and-receive-an-icmp-response-from-router-in-c
void udp_scan(std::string dest_IP, const int dest_port) {
    
    // buffers to send/receive
    char datagram[PCKT_LEN], recv_buff[PCKT_LEN];
    memset(datagram, 0, PCKT_LEN); // fill buffer with zero
    memset(recv_buff, 0, PCKT_LEN); // fill buffer with zero
    
    int send_sock, recv_sock;     // sockets

    struct sockaddr_in dest_addr, recv_addr;
    socklen_t recv_addr_len;
    
    send_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (send < 0) {
        error("ERROR! Unable to open send socket");
    }
    
    recv_sock = socket (AF_INET, SOCK_RAW|SOCK_NONBLOCK, IPPROTO_ICMP);
    if (recv_sock < 0) {
        error("ERROR! Unable to open receive socket");
    }

    // fill destination address fields
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(dest_port);
    dest_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    //Send the packet
    if (sendto (send_sock, datagram, sizeof(datagram), 0, (struct sockaddr*) &dest_addr, sizeof (dest_addr)) < 0) {
        error("ERROR! Unable to send");
    }

    recv_addr_len = sizeof(recv_addr);   
    ssize_t resp = recvfrom(recv_sock, recv_buff, sizeof(recv_buff), 0, (struct sockaddr*) &recv_addr, &recv_addr_len);

    struct iphdr *iph = (struct iphdr *) recv_buff;
    unsigned short iphdrlen = iph->ihl*4;
    struct icmphdr *icmph = (struct icmphdr *)(recv_buff + iphdrlen);

    printf("%s\n", inet_ntoa(recv_addr.sin_addr));
    printf("%d\n", ntohs(recv_addr.sin_port));      // using icmph->source or ->dest does not work either

    close(send_sock);
    close(recv_sock);
}

int main(int argc, char *argv[]) {
    // error check
    if (argc < 2) {
       fprintf(stderr,"usage %s hostname port\n", argv[0]);
       exit(0);
    }

    std::vector<int> ports = {20000};

    for(const auto port : ports) {
        udp_scan("localhost", port);
    }
    
    return 0;
}