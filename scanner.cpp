#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <unistd.h>
#include <stdlib.h>

#include <string.h>
#include <fstream>
#include <vector>
#include <unordered_map>
#include <algorithm>    // std::random_shuffle
#include <ctime>        // std::time
#include <cstdlib>      // std::rand, std::srand

static std::unordered_map<int,int> ports_status;
static std::vector<int> ports;

void error(const char *msg){
    perror(msg);
    exit(0);
}

// read ports from file
// Assuming format = one port number per line
std::vector<int> get_ports(std::string file_path) {
    std::vector<int> ports;

    std::ifstream file (file_path);
    if (file.is_open())
    {
        int port;
        while (file >> port)
        {
            ports.push_back(port);
        }
        file.close();
    } 
    else error("unable to retrieve ports from file"); 

    return ports;
}

std::unordered_map<int, int> get_port_status_map(std::string file_path) {
    std::unordered_map<int,int> ports_status;

    std::ifstream file (file_path);
    if (file.is_open())
    {
        int port;
        while (file >> port)
        {
            // initilize all ports status with false
            ports_status[port] = -1;
        }
        file.close();
    } 
    else error("unable to retrieve ports from file"); 

    return ports_status;
}

void scan(const std::string host) {
    int sock_fd, status;
    struct sockaddr_in server_addr;           // Socket address structure
    struct hostent *server;

    // create socket end point
    sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock_fd < 0) {
        error("ERROR! Unable to open socket");
    }

    // map IP to host
    server = gethostbyname(host.c_str());
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }

    // set same domain family as client socket
    server_addr.sin_family = AF_INET;

    // Fill in fields for server_addr
    memcpy((char *)&server_addr.sin_addr.s_addr,
           (char *)server->h_addr,
           server->h_length);

    // shuffle ports
    std::random_shuffle(ports.begin(), ports.end());

    for(const auto port : ports) {
        // Specify server port number
        server_addr.sin_port = htons(port);

        // Connect to remote host address
        status = connect(sock_fd, (struct sockaddr *) &server_addr, sizeof(server_addr));

        // set scanned ports status
        ports_status[port] = status;
    }
  
    // close socket
    close(sock_fd);
}

int main() {
    // read ports from file into vector
    ports = get_ports("ports.txt");

    // read ports from file into map<int port, int status>
    ports_status = get_port_status_map("ports.txt");

    // initilize with safe hosts to scan (for now)
    // TODO data structure to mapping hosts to ports
    std::vector<std::string> hosts = {"localhost"};

    // set seed for random_shuffle()
    std::srand(unsigned(std::time(0)));

    // shuffle hosts
    std::random_shuffle(hosts.begin(), hosts.end());

    for(const auto host : hosts) {
        scan(host);
    }

    // debugging
    for(const auto port : ports) {
        printf("%d: %d\n", port, ports_status[port]);
    }

    return 0;
}