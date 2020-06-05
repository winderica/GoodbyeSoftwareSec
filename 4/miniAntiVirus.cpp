#include <bits/stdc++.h>
#include <botan/hash.h>
#include <botan/hex.h>
#include <parser-library/parse.h>

using namespace std;
using namespace peparse;
namespace fs = filesystem;

using ParsedPeRef = unique_ptr<peparse::parsed_pe, void (*)(peparse::parsed_pe *)>;

ParsedPeRef openExecutable(const string &path) noexcept {
    ParsedPeRef obj(peparse::ParsePEFromFile(path.data()), peparse::DestructParsedPE);
    if (!obj) {
        return {nullptr, peparse::DestructParsedPE};
    }
    return obj;
}

inline uint8_t hex2char(char c) {
    return isupper(c) ? c - 'A' + 10 : islower(c) ? c - 'a' + 10 : c - '0';
}

string hex2bytes(const string &hex) {
    string bytes;
    auto length = hex.length();
    auto i = 0;
    while (i < length) {
        if (!isalnum(hex[i])) {
            return "";
        }
        auto msn = hex2char(hex[i++]);
        auto lsn = hex2char(hex[i++]);
        bytes.push_back(msn * 16 + lsn);
    }
    return bytes;
}

string hex2regex(const string &hex) {
    string bytes = "^"; // to get rid of huge time consumption
    auto length = hex.length();
    auto i = 0;
    while (i < length) {
        switch (hex[i]) {
            case '*': { // *
                i++;
                bytes.append(".*");
                break;
            }
            case '?': { // ?? or ?a
                i += 2;
                bytes.append(".");
                break;
            }
            case '{': {
                i++;
                auto n = 0;
                auto m = 0;
                if (hex[i] == '-') { // {-n}
                    i++;
                    while (isdigit(hex[i])) {
                        n = n * 10 + (hex[i] - '0');
                        i++;
                    }
                    if (n > 1000) {
                        return "";
                    }
                    i++;
                    bytes.append(".{0,").append(to_string(n)).append("}");
                    break;
                }
                while (isdigit(hex[i])) {
                    n = n * 10 + (hex[i] - '0');
                    i++;
                }
                if (n > 1000) {
                    return "";
                }
                if (hex[i] == '}') { // {n}
                    i++;
                    bytes.append(".{").append(to_string(n)).append("}");
                    break;
                }
                i++;
                if (hex[i] == '}') { // {n-}
                    i++;
                    bytes.append(".{").append(to_string(n)).append(",}");
                    break;
                }
                while (isdigit(hex[i])) { // {n-m}
                    m = m * 10 + (hex[i] - '0');
                    i++;
                }
                i++;
                if (m > 1000) {
                    return "";
                }
                bytes.append(".{").append(to_string(n)).append(",").append(to_string(m)).append("}");
                break;
            }
            case '(':
            case '|':
            case ')': { // capture group
                bytes.push_back(hex[i++]);
                break;
            }
            case '[': { // ...
                return "";
            }
            default: {
                if (hex[i + 1] == '?') { // a?
                    bytes.append(".");
                    i += 2;
                } else { // hex
                    bytes.append("\\x");
                    bytes.push_back(hex[i++]);
                    bytes.push_back(hex[i++]);
                }
            }
        }
    }
    return bytes;
}

string sha256(const string &input) {
    auto hash = Botan::HashFunction::create_or_throw("SHA-256");
    hash->update(input);
    return Botan::hex_encode(hash->final(), false);
}

string sha1(const string &input) {
    auto hash = Botan::HashFunction::create_or_throw("SHA-1");
    hash->update(input);
    return Botan::hex_encode(hash->final(), false);
}

string md5(const string &input) {
    auto hash = Botan::HashFunction::create_or_throw("MD5");
    hash->update(input);
    return Botan::hex_encode(hash->final(), false);
}

string md5(uint8_t *input, uint32_t length) {
    auto hash = Botan::HashFunction::create_or_throw("MD5");
    hash->update(input, length);
    return Botan::hex_encode(hash->final(), false);
}

bool boyerMooreMatch(const string &str, const string &pattern) {
    auto it = search(str.begin(), str.end(), boyer_moore_searcher(pattern.begin(), pattern.end()));
    return it != str.end();
}

string readFile(const string &filename) {
    auto file = ifstream(filename);
    stringstream contents;
    contents << file.rdbuf();
    file.close();
    return contents.str();
}

struct Section {
    uint32_t address;
    string digest;
};

int readSection(void *N, const VA &, const string &, const image_section_header &section, const bounded_buffer *data) {
    auto sections = static_cast<vector<Section> *>(N);
    sections->push_back({
        section.VirtualAddress,
        md5(data->buf, data->bufLen)
    });
    return 0;
}

vector<string> split(const string &str, const string &delimiter) {
    vector<string> tokens;
    size_t prev = 0, pos;
    do {
        pos = str.find(delimiter, prev);
        if (pos == string::npos) pos = str.length();
        auto token = str.substr(prev, pos - prev);
        if (!token.empty()) tokens.push_back(token);
        prev = pos + delimiter.length();
    } while (pos < str.length() && prev < str.length());
    return tokens;
}

struct ExtendedSignature {
    string name;
    int type;
    string offset;
    string signature;
    regex re;
};

vector<ExtendedSignature> ndb;

unordered_map<string, string> hdb;

unordered_map<string, string> hsb;

unordered_map<string, string> mdb;

void parseNDB(const string &file) {
    auto ifs = ifstream(file);
    string row;
    while (getline(ifs, row)) {
        auto v = split(row, ":");
        auto type = stoi(v.at(1));
        if (type == 1) { // PE
            auto signature = hex2bytes(v.at(3));
            auto re = regex();
            if (signature.empty()) {
                auto reRaw = hex2regex(v.at(3));
                if (reRaw.empty()) {
                    continue;
                }
                re = reRaw;
            }
            ndb.push_back(
                {
                    v.at(0),
                    type,
                    v.at(2),
                    signature,
                    re
                }
            );
        }
    }
}

void parseHDB(const string &file) {
    auto ifs = ifstream(file);
    string row;
    while (getline(ifs, row)) {
        auto v = split(row, ":");
        hdb.insert({v.at(0), v.at(2)});
    }
}

void parseHSB(const string &file) {
    auto ifs = ifstream(file);
    string row;
    while (getline(ifs, row)) {
        auto v = split(row, ":");
        hsb.insert({v.at(0), v.at(2)});
    }
}

void parseMDB(const string &file) {
    auto ifs = ifstream(file);
    string row;
    while (getline(ifs, row)) {
        auto v = split(row, ":");
        mdb.insert({v.at(1), v.at(2)});
    }
}

void getPosition(int &position, vector<Section> &sections, uint32_t entryPoint, const char *offset) {
    if (offset[0] == 'S') {
        if (offset[1] == 'E') { // SEx
            auto x = 0;
            offset += 2;
            while (isdigit(*offset)) {
                x = x * 10 + (*offset - '0');
                offset++;
            }
            if (x < sections.size()) {
                position = min(sections.at(x).address, static_cast<uint32_t>(position));
            }
        } else if (offset[1] == 'L') { // SL+n
            auto n = 0;
            offset += 2;
            auto sign = *offset == '+' ? 1 : -1;
            offset++;
            while (isdigit(*offset)) {
                n = n * 10 + (*offset - '0');
                offset++;
            }
            position = min(sections.back().address + sign * n, static_cast<uint32_t>(position));
        } else { // Sx+n
            auto x = 0;
            auto n = 0;
            offset++;
            while (isdigit(*offset)) {
                x = x * 10 + (*offset - '0');
                offset++;
            }
            auto sign = *offset == '+' ? 1 : -1;
            offset++;
            while (isdigit(*offset)) {
                n = n * 10 + (*offset - '0');
                offset++;
            }
            if (x < sections.size()) {
                position = min(sections.at(x).address + sign * n, static_cast<uint32_t>(position));
            }
        }
    } else if (offset[0] == 'E') {
        if (offset[1] == 'P') { // EP+-n
            auto n = 0;
            offset += 2;
            auto sign = *offset == '+' ? 1 : -1;
            offset++;
            while (isdigit(*offset)) {
                n = n * 10 + (*offset - '0');
                offset++;
            }
            position = min(entryPoint + sign * n, static_cast<uint32_t>(position));
        } else { // EOF-n
            auto n = 0;
            offset++;
            auto sign = *offset == '+' ? 1 : -1;
            offset++;
            while (isdigit(*offset)) {
                n = n * 10 + (*offset - '0');
                offset++;
            }
            position += sign * n;
        }
    } else if (offset[0] == '*') { // *
        position = -1;
    } else { // n
        auto n = 0;
        while (isdigit(*offset)) {
            n = n * 10 + (*offset - '0');
            offset++;
        }
        position = min(position, n);
    }
}

unordered_map<string, vector<string>> scanned;

void scan(const fs::path &path) {
    if (fs::is_directory(path)) {
        for (auto &p: fs::directory_iterator(path)) {
            scan(p.path());
        }
    } else {
        auto file = readFile(path);
        auto fileSize = file.length();
        auto sha256Digest = sha256(file);
        auto sha1Digest = sha1(file);
        auto md5Digest = md5(file);
        if (!scanned.count(sha256Digest)) {
            vector<string> names;
            if (hdb.count(md5Digest)) {
                names.push_back(hdb[md5Digest]);
            } else if (hsb.count(sha1Digest)) {
                names.push_back(hsb[sha1Digest]);
            } else {
                auto pe = openExecutable(path);
                if (!pe) {
                    return;
                }
                vector<Section> sections;
                IterSec(pe.get(), readSection, &sections);
                for (const auto &section: sections) {
                    if (mdb.count(section.digest)) {
                        names.push_back(mdb[section.digest]);
                    }
                }
                if (names.empty()) {
                    string line;
                    uint32_t entryPoint;
                    if (pe->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
                        entryPoint = pe->peHeader.nt.OptionalHeader.AddressOfEntryPoint;
                    } else {
                        entryPoint = pe->peHeader.nt.OptionalHeader64.AddressOfEntryPoint;
                    }
                    for (const auto &[name, type, offset, signature, re]: ndb) {
                        int position = fileSize;
                        getPosition(position, sections, entryPoint, offset.c_str());
                        if (signature.empty()) {
                            if (position >= 0) {
                                auto f = file.substr(position);
                                if (regex_match(f, re)) {
                                    names.push_back(name);
                                }
                            }
                        } else {
                            if ((position < 0 && boyerMooreMatch(file, signature))
                                || (position >= 0 && file.substr(position).rfind(signature, 0) == 0)) {
                                names.push_back(name);
                            }
                        }
                    }
                }
            }
            scanned.insert({sha256Digest, names});
        }
        if (!scanned[sha256Digest].empty()) {
            cout << "===========================================" << endl
                 << "File: " << path.filename() << endl
                 << "Size: " << fileSize << endl
                 << "Path: " << path << endl
                 << "MD5 Digest: " << md5Digest << endl
                 << "SHA1 Digest: " << sha1Digest << endl
                 << "SHA256 Digest: " << sha256Digest << endl
                 << "Virus Name: ";
            for (const auto &name: scanned[sha256Digest]) {
                cout << name << " ";
            }
            cout << endl;
        }
    }
}

int main(int argc, char **argv) {
    if (argc != 6) {
        cout << "Usage: " << argv[0] << " <path_to_scan> <ndb> <hdb> <hsb> <mdb>" << endl;
        return 1;
    }
    auto path = argv[1];
    parseNDB(argv[2]);
    parseHDB(argv[3]);
    parseHSB(argv[4]);
    parseMDB(argv[5]);
    cout << "Scanning " << path << " ..." << endl;
    scan(path);
}