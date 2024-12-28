#include <iostream>
#include <fstream>
#include <openssl/evp.h>
#include <sstream>
#include <iomanip>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <condition_variable>

std::string calculateMD5(const std::string& input) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        std::cerr << "Failed to create EVP_MD_CTX\n";
        return "";
    }

    const EVP_MD* md = EVP_md5();
    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        std::cerr << "Failed to initialize MD5 digest\n";
        return "";
    }

    if (EVP_DigestUpdate(ctx, input.c_str(), input.length()) != 1) {
        EVP_MD_CTX_free(ctx);
        std::cerr << "Failed to update MD5 digest\n";
        return "";
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;
    if (EVP_DigestFinal_ex(ctx, hash, &lengthOfHash) != 1) {
        EVP_MD_CTX_free(ctx);
        std::cerr << "Failed to finalize MD5 digest\n";
        return "";
    }

    EVP_MD_CTX_free(ctx);

    std::ostringstream oss;
    for (unsigned int i = 0; i < lengthOfHash; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return oss.str();
}

std::vector<char> readConfigFile(const std::string& configFilePath) {
    std::ifstream file(configFilePath);
    std::string temp;
    getline(file, temp);
    std::vector<char> charset(temp.begin(), temp.end());
    return charset;
}

std::atomic<int> currWaiting{ 0 };
std::atomic<int> currThreads{ 0 };
std::atomic<int> counter{ 0 };
std::shared_mutex sm;
std::mutex nm;
std::mutex fa;
std::mutex reduce_mutex;
std::condition_variable_any cva1;
std::condition_variable_any cva2;
std::condition_variable_any cva3;
std::atomic<bool> notified{ false };
std::atomic<bool> allDone{ false };
std::atomic<bool> allFinished{ true };
bool outputDone = false;

void findFromCurrent(const std::string& targetHash, const std::vector<char>& charset, std::map<char, int>& mpChars, std::string current,
    bool& found, std::string& result, std::map<std::pair<int, char>, std::string>& mp) {

    int length = static_cast<int>(current.size());

    if (calculateMD5(current) == targetHash) {
        found = true;
        result = current;
        cva1.notify_one();
        return;
    }
    mp[{length, current[0]}] = current;

    std::string target = (current[0] + std::string(length - 1, charset.back()));
    char frontChar = charset.front(), backChar = charset.back();

    while (current != target) {
        for (int i = length - 1; i >= 1; i--) {
            if (current[i] == backChar) {
                current[i] = frontChar;
            }
            else {
                current[i] = charset[mpChars[current[i]] + 1];
                mp[{length, current[0]}] = current;

                counter.fetch_add(1);

                if (calculateMD5(current) == targetHash) {
                    found = true;
                    result = current;
                    cva1.notify_one();
                    return;
                }

                if (current == target) {
                    std::unique_lock<std::mutex> reduce_lock(reduce_mutex);
                    mp.erase({ length,current[0] });
                    currThreads.fetch_add(-1);
                    if (currThreads.load() == 0) cva1.notify_one();
                    reduce_lock.unlock();
                    return;
                }

                if (counter.load() > 10000) {
                    std::shared_lock<std::shared_mutex> sl(sm);
                    cva3.wait(sl, [] { return allFinished.load(); });
                    currWaiting.fetch_add(1);
                    while (currWaiting.load() != currThreads.load()) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    }

                    std::unique_lock<std::mutex> nul(nm);
                    if (!(notified.load())) {
                        allFinished.store(false);
                        allDone.store(true);
                        notified.store(true);
                        cva1.notify_one();
                    }
                    nul.unlock();

                    cva2.wait(sl, [] {return outputDone; });

                    std::unique_lock<std::mutex> ul(fa);
                    currWaiting.fetch_add(-1);

                    counter.store(0);

                    if (currWaiting.load() == 0) {
                        outputDone = false;
                        allFinished.store(true);
                        notified.store(false);
                        cva3.notify_all();
                    }
                }
                break;
            }
        }
    }
    std::unique_lock<std::mutex> reduce_lock_2(reduce_mutex);
    mp.erase({ length,current[0] });
    currThreads.fetch_add(-1);
    if (currThreads.load() == 0) cva1.notify_one();
}

void startSearch(std::string& targetHash, std::vector<char>& charset, int maxLength, std::map<std::pair<int, char>, std::string>& mp) {
    bool found = false;
    std::string result = "";
    int charSize = static_cast<int>(charset.size());

    std::map<char, int> mpChars;
    for (int i = 0; i < charset.size(); i++) {
        mpChars[charset[i]] = i;
    }

    if (mp.size() != 0) {
        currThreads.store(maxLength);
        for (const auto& p : mp) {
            std::thread t(
                findFromCurrent, targetHash, charset, std::ref(mpChars), p.second,
                std::ref(found), std::ref(result), std::ref(mp));
            t.detach();
        }
    }
    else {
        currThreads.store(maxLength * charSize);
        for (int i = 1; i <= maxLength; i++) {
            for (int j = 0; j < charSize; j++) {
                std::thread t(
                    findFromCurrent, targetHash, charset, std::ref(mpChars), charset[j] + std::string(i - 1, charset[0]),
                    std::ref(found), std::ref(result), std::ref(mp));
                t.detach();
            }
        }
    }

    while (!found && currThreads.load() != 0) {
        std::unique_lock<std::shared_mutex> ul(sm);
        cva1.wait(ul, [&] { return found || allDone.load() || (currThreads.load() == 0); });

        std::ofstream fout("buffer.txt");
        if (found) {
            fout << "found" << ' ' << result;
            break;
        }
        fout << targetHash << ' ';
        for (int i = 0; i < charset.size(); i++) fout << charset[i];
        fout << ' ' << currThreads.load() << ' ';

        std::cout << "Current situation:\t";
        for (const auto& p : mp) {
            std::cout << p.second << ' ' << p.first.first << '\t';
            fout << p.second << ' ';
        }
        std::cout << '\n';

        fout.close();

        outputDone = true;
        allDone.store(false);
        cva2.notify_all();
    }

    if (found) {
        std::cout << "original string found: \"" << result << "\"\n";
    }
    else {
        std::cout << "not found\n" << '\n';
    }
}

int main(int argc, char* argv[]) {
    std::string targetHash;
    std::map<std::pair<int, char>, std::string> mp;

    if (argc == 3) {
        std::string configFilePath;
        targetHash = argv[1];
        configFilePath = argv[2];
        std::vector<char> charset = readConfigFile(configFilePath);

        if (charset.empty()) {
            if (targetHash == "d41d8cd98f00b204e9800998ecf8427e") {
                std::ofstream fout("buffer.txt");
                fout << "found ";
                std::cout << "Your string is empty: \"\"\n";
                return 0;
            }
            std::cerr << "Config file is empty or could not be read.\n";
            return -1;
        }

        std::cout << "Please, enter maximum length of string\n";
        int maxLength;
        std::cin >> maxLength;
        std::cout << "Finding...\n" << "Press Ctrl+C to stop\n";

        startSearch(targetHash, charset, maxLength, mp);
    }
    else if (argc == 2) {
        if (std::string(argv[1]) != "resume") {
            std::cout << "Usage: inverse_md5_calc.exe resume\n";
            return -1;
        }

        std::ifstream fin("buffer.txt");
        std::string temp;
        fin >> temp;
        if (temp == "") {
            std::cout << "Please, start main program before resume\n";
            return -1;
        }
        else if (temp == "not_found") {
            std::cout << "String not found\n";
            return -1;
        }
        else if (temp == "found") {
            if (!(fin >> temp)) {
                std::cout << "Original string is empty: \"\"\n";
                return 0;
            }
            std::cout << "Original string is: " << temp << '\n';
            return 0;
        }

        targetHash = temp;
        std::string strChars;
        fin >> strChars;
        std::vector<char> charset(strChars.begin(), strChars.end());
        int continueThreads;
        fin >> continueThreads;
        while (fin >> temp) {
            mp[{(int)temp.length(), temp[0]}] = temp;
        }

        fin.close();
        std::cout << "Continuing from this point:\n";
        for (const auto& p : mp) {
            std::cout << "Length:\t" << p.first.first << "\t current word: " << p.second << '\n';
        }
        std::cout << "Finding...\n" << "Press Ctrl+C to stop\n";
        startSearch(targetHash, charset, continueThreads, mp);
        return 0;
    }
    else {
        std::cout << "Usage: inverse_md5_calc.exe <hash> <path_to_config>\n";
    }
}