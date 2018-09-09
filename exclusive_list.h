#include <list>
#include <mutex>
#include <iostream>


// Trivial thread safety wrapper for std::list
template <class T>
class ExclusiveList {
public:
    ExclusiveList() {};

    void add(T value) {
        std::lock_guard<std::mutex> guard(m);
        l.push_back(value);
    };

    void remove(T value) {
        std::lock_guard<std::mutex> guard(m);
        l.remove(value);
    };

    // Print everything with an optional prefix which will be included in the critical zone
    void print_all(std::string prefix = "") {
        std::lock_guard<std::mutex> guard(m);

        if(!prefix.empty()) { std::cout << prefix << std::endl; }
        for(T item : l) {
            std::cout << item << std::endl;
        }
    };

    void write_to_file(void (*write_function)(std::list<T>), std::string) {
        std::lock_guard<std::mutex> guard(m);
        (*write_function)(l);
    }

    std::list<T> get_list_copy() {
        std::lock_guard<std::mutex> guard(m);
        return l;
    }

    std::list<T>* get_list() {
        return &l;
    }

private:
    std::list<T> l;
    std::mutex m;
};