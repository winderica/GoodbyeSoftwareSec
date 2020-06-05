#include <filesystem>

using namespace std;
namespace fs = filesystem;

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: %s 0 <max> <frequency>\n", argv[0]);
        return 0;
    }
    auto filename = fs::path(argv[0]).filename().string();
    auto current = stoi(argv[1]);
    auto max = stoi(argv[2]);
    auto frequency = stoi(argv[3]);
    if (current <= max) {
        for (auto i = 1; i <= frequency; i++) {
            auto j = to_string(2 * current + i);
            fs::create_directory(j);
            fs::copy(filename, j + "/", fs::copy_options::overwrite_existing);
            system(("cd " + j + " && ./" + filename + " " + j + " " + argv[2] + " " + argv[3]).c_str());
        }
    }
}