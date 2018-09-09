#include <fstream>
#include <vector>

struct result {
    std::string ip;
    std::string port;
    std::string comment;
};

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

    // Return empty vector if file could not be read
    return ports;
}

void csv_append_results(struct result line, std::string fileName="results.csv") {
    std::ofstream file;
    file.open(fileName, std::ios_base::app);

    file << line.ip << ", " << line.port << ", " << line.comment << std::endl;
}

int remove_results_file(std::string fileName="results.csv") {
    return remove(fileName.c_str());
}