#include <fstream>
#include <vector>

void error(const char *msg){
    perror(msg);
    exit(0);
}

// read ports from file
// Assuming format = one port number per line
std::vector<int> get_lines(std::string file_path) {
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
