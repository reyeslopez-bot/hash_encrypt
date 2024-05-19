#include <Eigen/Dense>
#include <iostream>
#include <fstream>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <queue>
#include <string>
#include <random>
#include <memory>
#include <exception>
#include <chrono>
#include <iomanip>
#include <sstream>

class Logger {
public:
    enum Level { Debug, Info, Error };

    static std::queue<std::pair<std::string, Level>> logQueue;
    static std::mutex mtx;
    static std::condition_variable cv;
    static bool finished;

    static void log(const std::string& message, Level level) {
        std::lock_guard<std::mutex> lock(mtx);
        auto now = std::chrono::system_clock::now();
        auto now_time = std::chrono::system_clock::to_time_t(now);
        std::ostringstream oss;
        oss << std::put_time(std::localtime(&now_time), "%Y-%m-%d %H:%M:%S") << " - ";
        switch (level) {
            case Debug: oss << "DEBUG: "; break;
            case Info: oss << "INFO: "; break;
            case Error: oss << "ERROR: "; break;
        }
        oss << message;
        logQueue.push({oss.str(), level});
        cv.notify_one();
    }

    static void worker() {
        std::unique_lock<std::mutex> lock(mtx);
        while (!finished || !logQueue.empty()) {
            cv.wait(lock, [] { return !logQueue.empty() || finished; });
            while (!logQueue.empty()) {
                auto log = logQueue.front();
                logQueue.pop();
                lock.unlock();
                std::cout << log.first << std::endl;
                lock.lock();
            }
        }
    }
};

// Static member variable definitions
std::queue<std::pair<std::string, Logger::Level>> Logger::logQueue;
std::mutex Logger::mtx;
std::condition_variable Logger::cv;
bool Logger::finished = false;

class KeyGenerator {
public:
    KeyGenerator(int key_size, int modulus)
        : key_size(key_size), q(modulus), gen(std::random_device{}()), dist(-q/2, q/2) {
        Logger::log("KeyGenerator initialized with key size and modulus.", Logger::Debug);
    }

    Eigen::MatrixXi generate_secret_key() {
        try {
            Eigen::MatrixXi key(key_size, key_size);
            for (int i = 0; i < key_size; ++i) {
                for (int j = 0; j < key_size; ++j) {
                    key(i, j) = dist(gen);
                }
            }
            Logger::log("Secret key generated successfully.", Logger::Info);
            return key;
        } catch (const std::exception& e) {
            Logger::log("Failed to generate secret key: " + std::string(e.what()), Logger::Error);
            throw;
        }
    }

    Eigen::MatrixXi generate_public_key(const Eigen::MatrixXi& secret_key) {
        try {
            Eigen::MatrixXi error_matrix = generate_error_matrix(key_size, key_size);
            Eigen::MatrixXi temp = secret_key * error_matrix;
            temp += generate_error_matrix(key_size, key_size);
            return temp.unaryExpr([this](int x) { return ((x % q) + q) % q; });
        } catch (const std::exception& e) {
            Logger::log("Failed to generate public key: " + std::string(e.what()), Logger::Error);
            throw;
        }
    }

private:
    int key_size;
    int q;
    std::mt19937 gen;
    std::uniform_int_distribution<> dist;

    Eigen::MatrixXi generate_error_matrix(int rows, int cols) {
        try {
            Eigen::MatrixXi matrix(rows, cols);
            for (int i = 0; i < rows; ++i) {
                for (int j = 0; j < cols; ++j) {
                    matrix(i, j) = dist(gen);
                }
            }
            return matrix;
        } catch (const std::exception& e) {
            Logger::log("Failed to generate error matrix: " + std::string(e.what()), Logger::Error);
            throw;
        }
    }
};

class LatticeCrypto {
private:
    int security_level;
    std::unique_ptr<KeyGenerator> key_gen;
    Eigen::MatrixXi secret_key;
    Eigen::MatrixXi public_key;

    Eigen::MatrixXi padPlaintext(const std::string& plaintext, int size) {
        Eigen::MatrixXi padded(size, 1);
        for (int i = 0; i < size; ++i) {
            if (i < plaintext.length()) {
                padded(i, 0) = static_cast<int>(plaintext[i]);
            } else {
                padded(i, 0) = 0; // Zero padding
            }
        }
        return padded;
    }

    std::string matrixToString(const Eigen::MatrixXi& matrix) {
        std::string result;
        for (int i = 0; i < matrix.rows(); ++i) {
            int val = matrix(i, 0);
            if (val >= 32 && val <= 126) { // Printable ASCII range
                result += static_cast<char>(val);
            }
        }
        return result;
    }

public:
    LatticeCrypto(int security_level = 128) {
        Logger::log("Initializing LatticeCrypto with security level " + std::to_string(security_level), Logger::Debug);
        int key_size, q;
        if (security_level == 128) {
            key_size = 512;
            q = 4096;
        } else if (security_level == 256) {
            key_size = 1024;
            q = 15331;
        } else {
            Logger::log("Unsupported security level provided: " + std::to_string(security_level), Logger::Error);
            throw std::invalid_argument("Unsupported security level: " + std::to_string(security_level));
        }

        key_gen = std::make_unique<KeyGenerator>(key_size, q);
        secret_key = key_gen->generate_secret_key();
        public_key = key_gen->generate_public_key(secret_key);
        Logger::log("LatticeCrypto initialized successfully.", Logger::Info);
    }

    Eigen::MatrixXi encrypt(const std::string& plaintext) {
        Eigen::MatrixXi plaintext_vector = padPlaintext(plaintext, public_key.rows());
        return public_key * plaintext_vector;
    }

    std::string decrypt(const Eigen::MatrixXi& ciphertext) {
        try {
            Logger::log("Starting decryption process.", Logger::Debug);

            Logger::log("Secret key dimensions: " + std::to_string(secret_key.rows()) + "x" + std::to_string(secret_key.cols()), Logger::Debug);
            Logger::log("Ciphertext dimensions: " + std::to_string(ciphertext.rows()) + "x" + std::to_string(ciphertext.cols()), Logger::Debug);

            if (secret_key.rows() != ciphertext.rows()) {
                Logger::log("Dimension mismatch: secret key rows (" + std::to_string(secret_key.rows()) + 
                            ") and ciphertext rows (" + std::to_string(ciphertext.rows()) + ")", Logger::Error);
                throw std::runtime_error("Mismatch in dimensions between secret key and ciphertext.");
            }

            Eigen::FullPivLU<Eigen::MatrixXd> lu_decomp(secret_key.cast<double>());
            if (!lu_decomp.isInvertible()) {
                Logger::log("Secret key matrix is not invertible.", Logger::Error);
                throw std::runtime_error("Secret key matrix is not invertible.");
            }

            Eigen::MatrixXd plaintext_vector_double = lu_decomp.inverse() * ciphertext.cast<double>();

            std::ostringstream oss;
            oss << "Plaintext vector (double) values:\n" << plaintext_vector_double;
            Logger::log(oss.str(), Logger::Debug);

            Eigen::MatrixXi plaintext_vector = plaintext_vector_double.cast<int>().unaryExpr([](int x) {
                return ((x % 256) + 256) % 256;
            });

            oss.str("");
            oss.clear();
            oss << "Normalized plaintext vector (int) values:\n" << plaintext_vector;
            Logger::log(oss.str(), Logger::Debug);

            std::string decrypted_text = matrixToString(plaintext_vector);

            Logger::log("Decryption completed successfully.", Logger::Info);
            return decrypted_text;

        } catch (const std::exception& e) {
            Logger::log("Decryption failed: " + std::string(e.what()), Logger::Error);
            throw; // Re-throw the exception after logging
        }
    }
};

int main() {
    Logger::log("Main function started.", Logger::Debug);
    std::thread loggerThread(Logger::worker);

    try {
        LatticeCrypto crypto(128);
        std::string plaintext = "Hello, world!";

        Eigen::MatrixXi ciphertext = crypto.encrypt(plaintext);
        std::cout << "Encrypted: " << ciphertext << std::endl;

        std::string decryptedText = crypto.decrypt(ciphertext);
        std::cout << "Decrypted text: " << decryptedText << std::endl;
    } catch (const std::exception& e) {
        Logger::log("An error occurred: " + std::string(e.what()), Logger::Error);
    }
    Logger::finished = true;
    Logger::cv.notify_one();
    loggerThread.join();

    Logger::log("Main function completed.", Logger::Info);
    return 0;
}