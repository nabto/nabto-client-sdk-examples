#pragma once

#include <fstream>

namespace nabto {
namespace examples {
namespace common {

class File {
 public:
    static bool exists(const std::string& path)
    {
        std::ifstream f(path);
        return (f.is_open() && !f.fail());
    }

    static bool readFile(const std::string& path, std::string& content)
    {
        try {
            std::ifstream f(path);
            std::string str((std::istreambuf_iterator<char>(f)),
                            std::istreambuf_iterator<char>());
            content = str;
            return true;
        } catch (std::exception &e) {
            return false;
        }
    }

    static bool writeFile(const std::string& path, const std::string& content)
    {
        try {
            std::ofstream f(path);
            f << content;
            return true;
        } catch (std::exception &e) {
            return false;
        }
    }
};

} } } // namespace
