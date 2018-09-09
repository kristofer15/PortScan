#include <stdio.h> //printf
#include <string.h> //memset
#include <stdlib.h> //for exit(0);
#include <sys/socket.h>
#include <errno.h> //For errno - the error number
#include <netdb.h> //hostend
#include <arpa/inet.h>
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/ip.h>    //Provides declarations for ip header
#include <unistd.h>
#include <time.h>

#include <thread>
#include <mutex>
#include <vector>
#include <list>
#include <algorithm>    // std::random_shuffle
#include <iostream>

#include "file_io.h"
#include "exclusive_list.h"

// TODO: CHANGE ME PROBABLY
std::mutex IO_MUTEX;

// From: https://www.binarytides.com/tcp-syn-portscan-in-c-with-linux-sockets/
struct pseudo_header {
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
     
    struct tcphdr tcp;
};

char *int_to_ip(uint32_t address) {
    struct in_addr ip_addr;
    ip_addr.s_addr = address;
    return inet_ntoa(ip_addr);
} 

// From: https://www.binarytides.com/tcp-syn-portscan-in-c-with-linux-sockets/
unsigned short csum(unsigned short *ptr,int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;
 
    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }
 
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer = (short)~sum;
     
    return(answer);
}

// Modified from: https://www.binarytides.com/tcp-syn-portscan-in-c-with-linux-sockets/
uint32_t get_local_address()
{
    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));

    int sock = socket ( AF_INET, SOCK_DGRAM, 0);
 
    const char* kGoogleDnsIp = "8.8.8.8";
    int dns_port = 53;
 
    struct sockaddr_in serv;
 
    memset( &serv, 0, sizeof(serv) );
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
    serv.sin_port = htons( dns_port );
 
    int err = connect( sock , (const struct sockaddr*) &serv , sizeof(serv) );
 
    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    err = getsockname(sock, (struct sockaddr*) &name, &namelen);
    close(sock);

    return name.sin_addr.s_addr;
}

// From: https://www.binarytides.com/tcp-syn-portscan-in-c-with-linux-sockets/
struct iphdr* get_ip_header(char *datagram, uint32_t source_address, uint32_t destination_address) {
    struct iphdr *iph = (struct iphdr *) datagram;

    //Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
    iph->id = htons (3525);
    iph->frag_off = htons(16384);
    iph->ttl = 20;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = source_address;
    iph->daddr = destination_address;
     
    iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);

    return iph;
}

// flag logic from: https://github.com/chinmay29/PortScanner/blob/master/PortScanner.cpp
// Structure from:  https://www.binarytides.com/tcp-syn-portscan-in-c-with-linux-sockets/
struct tcphdr* get_tcp_header(char *datagram, uint8_t flags) {
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct iphdr));

    //TCP Header
    tcph->source = 0; // Set later
    tcph->dest = 0; // Set later
    tcph->seq = htonl(3434);
    tcph->ack_seq = 0;
    tcph->doff = sizeof(struct tcphdr) / 4;
    tcph->fin = TH_FIN & flags ? 1 : 0;
    tcph->syn = TH_SYN & flags ? 1 : 0;
    tcph->rst = TH_RST & flags ? 1 : 0;
    tcph->psh = TH_PUSH & flags ? 1 : 0; // Why are you like this!?
    tcph->ack = TH_ACK & flags ? 1 : 0;
    tcph->urg = TH_URG & flags ? 1 : 0;
    tcph->window = htons ( 14600 );
    tcph->check = 0;
    tcph->urg_ptr = 0;

    return tcph;
}

void disable_os_header(int s) {
    int one = 1;
    const int *val = &one;
     
    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        std::cout << "Could not set IP_HDRINCL. Error number: " << errno << std::endl;
        std::cout << "Error message: " << strerror(errno) << std::endl;
        exit(0);
    }
}

void analyze_response(char *datagram, uint32_t server_address, ExclusiveList<int> &hit_ports, uint8_t desired_flags) {
    struct iphdr *iph = (struct iphdr *) datagram;
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof(iphdr));

    uint32_t received_address = iph->saddr;
    uint8_t received_flags = 0;

    // Collect received flags
    received_flags |= tcph->ack ? TH_ACK : 0;
    received_flags |= tcph->syn ? TH_SYN : 0;
    received_flags |= tcph->fin ? TH_FIN : 0;
    received_flags |= tcph->rst ? TH_RST : 0;

    if(server_address == received_address) {
        hit_ports.remove(ntohs(tcph->source));

        // We indicate no response desired with no flags desired
        if(desired_flags) {
            struct result line;
            line.ip = int_to_ip(server_address);
            line.port = std::to_string(ntohs(tcph->source));

            // received_flags are desired_flags and the address is correct
            if((received_flags == desired_flags) && (server_address == received_address)) {
                line.comment = "open";
            }
            else if(server_address == received_address) {
                line.comment = "closed";
            }

            std::lock_guard<std::mutex> guard(IO_MUTEX);
            csv_append_results(line);
        }
    }
}

void sniff(uint32_t server_address, ExclusiveList<int> &hit_ports, uint8_t desired_flags) {
    int response_size;

    char datagram[4096];
    memset(&datagram, 0, 4096);

    int s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    // select timeout from: https://programmersheaven.com/discussion/353252/how-to-set-timeout-for-recvfrom-method
    fd_set socks;
    FD_ZERO(&socks);
    FD_SET(s, &socks);
    struct timeval t;
    t.tv_sec = 3;

    while(true) {
        if(select(s+1, &socks, NULL, NULL, &t)) {
            response_size = recvfrom(s, datagram, sizeof(datagram), 0, NULL, NULL);

            if(response_size > 0) {
                analyze_response(datagram, server_address, hit_ports, desired_flags);
            }

            // Reset timer
            t.tv_sec = 3;
        }
        else {
            return;
        }
    }
}

void connect_tcp(const char *host_name, std::vector<int> &ports) {
    struct sockaddr_in destination_in;
    struct hostent *destination;

    char buffer[256];

    int s = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);

    destination = gethostbyname(host_name);

    bzero((char *) &destination_in, sizeof(destination_in));

    destination_in.sin_family = AF_INET;

    bcopy((char *)destination->h_addr,
    (char *)&destination_in.sin_addr.s_addr,
    destination->h_length);

    fd_set socks;
    FD_ZERO(&socks);
    FD_SET(s, &socks);
    struct timeval t;

    for(int port : ports) {
        destination_in.sin_port = htons(port);
        struct result line;
        line.ip = int_to_ip(destination_in.sin_addr.s_addr);
        line.port = std::to_string(port);

        // Reset select timeout on new connections
        t.tv_sec = 1;
        int status = connect(s, (struct sockaddr *) &destination_in, sizeof(destination_in));

        // Already connected
        if(status = 0) {
            line.comment = "open";
        }
        // Connection already failed
        else if(status != EINPROGRESS) {
            line.comment = "closed";
        }
        else {
            // Wait for a signal
            int state = select(s+1, &socks, NULL, NULL, &t);

            // Did a connection just finish?
            if(state && FD_ISSET(s, &socks)) {
                line.comment = "open";
            }
            else {
                line.comment = "closed";
            }
        }

        IO_MUTEX.lock();
        csv_append_results(line);
        IO_MUTEX.unlock();

        // Sleep for a random time interval between 0.5 and 0.8s
        usleep((rand() % 300000) + 500000);
    }
}

void hit_tcp(const char *host_name, std::vector<int> &ports, uint8_t out_flags, uint8_t in_flags) {
    struct sockaddr_in destination_in;
    struct hostent *destination;
    struct pseudo_header psh;
    ExclusiveList<int> hit_ports;

	int s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    //Datagram to represent the packet
    char datagram[4096];
    memset (&datagram, 0, 4096); /* zero out the buffer */

    // Get destination hostent
    destination = gethostbyname(host_name);
    bcopy((char *)destination->h_addr,
        (char *)&destination_in.sin_addr.s_addr,
        destination->h_length);

    // Get source address
    uint32_t source_address = get_local_address();
    uint32_t destination_address = destination_in.sin_addr.s_addr;

    if (destination == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }

    destination_in.sin_family = AF_INET;

    //IP header
    struct iphdr *iph = get_ip_header(datagram, source_address, destination_address);
    
    //TCP header
    struct tcphdr *tcph = get_tcp_header(datagram, out_flags);

    disable_os_header(s);

    std::thread sniffer_thread(sniff, destination_address, std::ref(hit_ports), in_flags);

    srand(time(NULL));  // Seed random function

    for(int destination_port : ports) {        
        tcph->source = htons((rand() % 2000) + 2000); // Get a random port in range 2000 - 3999
        tcph->dest = htons(destination_port);
        tcph->check = 0;
            
        psh.source_address = source_address;
        psh.dest_address = destination_address;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons( sizeof(struct tcphdr));
            
        memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));

        tcph->check = csum( (unsigned short*) &psh, sizeof (struct pseudo_header));

        if ( sendto (s, datagram, sizeof(struct iphdr) + sizeof(struct tcphdr) , 0 , (struct sockaddr *) &destination_in, sizeof (destination_in)) < 0)
        {
            // TODO: cout
            printf ("Error sending packet. Error number: %d . Error message: %s \n" , errno , strerror(errno));
            exit(0);
        }

        hit_ports.add(destination_port);

        // Sleep for a random time interval between 0.5 and 0.8s
        usleep((rand() % 300000) + 500000);
    }

    sniffer_thread.join();

    if(!in_flags) {
        std::list<int> hit_ports_final = hit_ports.get_list_copy();

        // Just lock for the entire duration of this threads write.
        // It's roughly as fast but should output grouped hosts.
        std::lock_guard<std::mutex> guard(IO_MUTEX);

        for(int port : ports) {
            struct result line;
            line.ip = int_to_ip(destination_address);
            line.port = std::to_string(port);
            
            std::list<int>::iterator it;
            it = std::find(hit_ports_final.begin(), hit_ports_final.end(), port);

            if(it != hit_ports_final.end()) {
                line.comment = "open";
            }
            else {
                line.comment = "closed";
            }

            csv_append_results(line);
        }
    }
}

void help(std::string programName="scanner") {
    std::cout << "Usage:" << std::endl;
    std::cout << programName << " -[snxfac] (Specify one)" << std::endl;
    std::cout << "SCAN TYPES: " << std::endl;
    std::cout << "-s: SYN scan" << std::endl;
    std::cout << "-n: NULL scan" << std::endl;
    std::cout << "-x: XMAS scan" << std::endl;
    std::cout << "-f: FIN scan" << std::endl;
    std::cout << "-a: SYN|ACK scan (not to be confused with ACK scan)" << std::endl;
    std::cout << "-c: TCP connect (Full handshake)" << std::endl;
}

void scan_host(int option, std::string host_name, std::vector<int> &ports) {

    // Don't pass c strings to this function. Not thread safe for some reason.
    switch(option) {
        case 's':   // SYN scan
            hit_tcp(host_name.c_str(), ports, TH_SYN, TH_SYN|TH_ACK);
            break;
        case 'n':   // NULL scan
            hit_tcp(host_name.c_str(), ports, 0, 0);
            break;
        case 'x':   // XMAS scan
            hit_tcp(host_name.c_str(), ports, 0b11111111, 0);
            break;
        case 'f':   // FIN scan
            hit_tcp(host_name.c_str(), ports, TH_FIN, 0);
            break;
        case 'a':   // SYN|ACK - TODO: Rename because of ambiguitiy with ACK scans
            hit_tcp(host_name.c_str(), ports, TH_SYN|TH_ACK, 0);
            break;
        case 'c':   // TCP Connect (Full handshake)
            connect_tcp(host_name.c_str(), ports);
            break;
        default:
            // Don't go here
            std::cout << "Scan option not recognized" << std::endl;
            exit(0);
            help();
    }

    std::lock_guard<std::mutex> guard(IO_MUTEX);
    std::cout << "Done scanning " << host_name << std::endl;
}

int main(int argc, char* argv[]) {
    remove_results_file();

    int c = -1;
    int option = -1;
    
    while((c = getopt(argc, argv, "snxfac")) != -1) {

        if(option != -1) {
            std::cout << "Too many scan options" << std::endl;
            help(argv[0]);
            exit(0);
        }
        
        option = c;
    }

    if(option == -1) {
        std::cout << "Scan option missing" << std::endl;
        help(argv[0]);
        exit(0);
    }

    std::vector<int> ports = get_lines<int>("ports.txt");
    std::vector<std::string> hosts = get_lines<std::string>("test_hosts.txt");

    // set seed for random_shuffle()
    std::srand(unsigned(std::time(0)));

    // Shuffle targets
    std::random_shuffle(ports.begin(), ports.end());
    std::random_shuffle(hosts.begin(), hosts.end());

    std::vector<std::thread> threads;
    for(std::string host : hosts) {
        std::cout << "Scanning " << host << std::endl;

        // Ports are in STL and should be read safe
        std::thread target_thread(scan_host, option, host, std::ref(ports));
        threads.push_back(std::move(target_thread));
    }

    // Join threads
    for(auto& thread : threads) {
        thread.join();
    }

    return 0;
}
