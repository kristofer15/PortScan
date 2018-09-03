#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <netinet/tcp.h>
#include <netinet/ip.h>

#include <netdb.h> 

void error(const char *msg)
{
    perror(msg);
    exit(0);
}

int main(int argc, char *argv[])
{
    int sockfd, portno, n;
    struct sockaddr_in serv_addr;           // Socket address structure
    struct hostent *server;
    struct tcphdr tcp;

    char buffer[256];
    
    if (argc < 3) {
       fprintf(stderr,"usage %s hostname port\n", argv[0]);
       exit(0);
    }

    memset(&tcp, 0, sizeof(tcp));

    //struct ipheader *iph = (struct ipheader *) buffer;
    //struct tcpheader *tcph = (struct tcpheader *) (buffer + sizeof(struct ip));
    tcp.th_sport = htons(4567);
    tcp.th_dport = htons(80);
    tcp.th_seq = 0;
    tcp.th_ack = 0;
    tcp.th_off = 5;
    tcp.th_flags = TH_SYN;
    tcp.th_win = htons(5840);
    tcp.th_sum = 0;
    tcp.th_urp = 0;

    portno = atoi(argv[2]);     // Read Port No from command line

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP); // Open Socket

    if (sockfd < 0) 
        error("ERROR opening socket");

    server = gethostbyname(argv[1]);        // Get host from IP

    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET; // This is always set to AF_INET

    // Host address is stored in network byte order
    bcopy((char *)server->h_addr, 
         (char *)&serv_addr.sin_addr.s_addr,
         server->h_length);

    serv_addr.sin_port = htons(portno);

    n = sendto(sockfd, &tcp, sizeof(tcp), 0, (struct sockaddr * )&serv_addr, sizeof(serv_addr));
    printf("Wrote %d bytes\n", n);
    
    /*
    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) 
        error("ERROR connecting");

    // Read and write to socket
    printf("Please enter the message: ");
    bzero(buffer,256);
    fgets(buffer,255,stdin);
    n = write(sockfd,buffer,strlen(buffer));

    if (n < 0) 
         error("ERROR writing to socket");

    bzero(buffer,256);
    n = read(sockfd,buffer,255);
    if (n < 0) 
         error("ERROR reading from socket");
    printf("%s\n",buffer);
    close(sockfd);

*/
    return 0;
}
