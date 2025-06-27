#include "memory_log.hpp"
#include <fstream>
#include <iostream>
#include <string>

void log_memory_usage(const std::string &filename)
{
    std::ifstream status_file("/proc/self/status");
    std::string line;
    std::ofstream out(filename, std::ios::app);

    while (std::getline(status_file, line))
    {
        if (line.rfind("VmRSS:", 0) == 0)
        {
            out << "[Memory] " << line << std::endl;
            break;
        }
    }
}
