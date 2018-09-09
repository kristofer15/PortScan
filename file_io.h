#include <fstream>
#include <vector>
#include <iostream>

struct result {
    std::string ip;
    std::string port;
    std::string comment;
};

template <class T>
std::vector<T> get_lines(std::string file_path) {
    std::vector<T> lines;

    std::ifstream file (file_path);
    if (file.is_open())
    {
        T line;
        while (file >> line)
        {
            lines.push_back(line);
        }
        file.close();
    }

    // Return empty vector if file could not be read
    return lines;
}

void csv_append_results(struct result line, std::string fileName="results.csv") {
    std::ofstream file;
    file.open(fileName, std::ios_base::app);

    file << line.ip << ", " << line.port << ", " << line.comment << std::endl;
}

int remove_results_file(std::string fileName="results.csv") {
    return remove(fileName.c_str());
}