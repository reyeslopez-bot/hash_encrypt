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
#include <cmath>
#include <cassert>
#include <atomic>
#include <unsupported/Eigen/FFT>

// Function to convert an Eigen vector to a string
std::string vector_to_string(const Eigen::VectorXi& vec) {
    std::stringstream ss;
    ss << vec.transpose();
    return ss.str();
}

namespace lattice_crypto {

// Logger class for handling multi-threaded logging
class Logger {
public:
    enum Level { Debug, Info, Error };

    static std::queue<std::pair<std::string, Level>> logQueue;
    static std::mutex mtx;
    static std::condition_variable cv;
    static std::atomic<bool> finished;

    static void log(const std::string& message, Level level) {
        {
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
        }
        cv.notify_one();
    }

    static void worker() {
        std::unique_lock<std::mutex> lock(mtx);
        while (!finished || !logQueue.empty()) {
            cv.wait(lock, [] { return !Logger::logQueue.empty() || Logger::finished; });
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
std::atomic<bool> Logger::finished = false;

// KeyGenerator class for generating Ring-LWE keys
class KeyGenerator {
public:
    KeyGenerator(int poly_degree, int modulus)
        : poly_degree(poly_degree), q(modulus), gen(std::random_device{}()), dist(-q / 2, q / 2) {
        Logger::log("KeyGenerator initialized with polynomial degree and modulus.", Logger::Debug);
    }

    Eigen::VectorXi generate_secret_key() {
        Eigen::VectorXi secret_key = generate_random_vector(poly_degree);
        Logger::log("Secret key generated successfully.", Logger::Info);
        Logger::log("Secret key: " + vector_to_string(secret_key), Logger::Debug);
        return secret_key;
    }

    std::pair<Eigen::VectorXi, Eigen::VectorXi> generate_public_key(const Eigen::VectorXi& secret_key) {
        Eigen::VectorXi a = generate_random_vector(poly_degree);
        Eigen::VectorXi e = generate_random_vector(poly_degree);
        Eigen::VectorXi b = polynomial_multiply(a, secret_key) + e;
        b = b.unaryExpr([this](int x) { return ((x % q) + q) % q; });
        Logger::log("Public key generated successfully.", Logger::Info);
        return {a, b};
    }

    Eigen::VectorXi generate_random_vector(int size) {
        Eigen::VectorXi vec(size);
        for (int i = 0; i < size; ++i) {
            vec[i] = dist(gen);
        }
        return vec;
    }

    Eigen::VectorXi polynomial_multiply(const Eigen::VectorXi& a, const Eigen::VectorXi& b) {
        Eigen::FFT<double> fft;
        std::vector<std::complex<double>> a_complex(a.data(), a.data() + a.size());
        std::vector<std::complex<double>> b_complex(b.data(), b.data() + b.size());

        std::vector<std::complex<double>> result_complex;
        fft.fwd(a_complex, a_complex);
        fft.fwd(b_complex, b_complex);

        result_complex.resize(a_complex.size());
        for (size_t i = 0; i < a_complex.size(); ++i) {
            result_complex[i] = a_complex[i] * b_complex[i];
        }

        fft.inv(result_complex, result_complex);

        Eigen::VectorXi result_int(result_complex.size());
        for (size_t i = 0; i < result_complex.size(); ++i) {
            result_int[i] = std::lround(result_complex[i].real()); // Use lround for better integer rounding
            result_int[i] = ((result_int[i] % q) + q) % q;         // Apply modulus here
        }

        result_int.conservativeResize(poly_degree);
        return result_int;
    }

private:
    int poly_degree;
    int q;
    std::mt19937 gen;
    std::uniform_int_distribution<> dist;
};

class RingLWECrypto {
private:
    int poly_degree;
    int q;
    Eigen::VectorXi secret_key;
    std::pair<Eigen::VectorXi, Eigen::VectorXi> public_key;
    std::unique_ptr<KeyGenerator> key_gen;

    Eigen::VectorXi modulate_vector(const Eigen::VectorXi& vec, int mod) {
        return vec.unaryExpr([mod](int x) { return ((x % mod) + mod) % mod; });
    }

    char normalize_char(int val) {
        val = ((val % 256) + 256) % 256;
        if (val < 32 || val > 126) {
            return '?'; // Non-printable characters are replaced with '?'
        }
        return static_cast<char>(val);
    }

    void pad_vector(Eigen::VectorXi& vec, int length, int pad_val = 0) {
        for (int i = length; i < poly_degree; ++i) {
            vec[i] = pad_val;
        }
    }

    std::string remove_padding(const std::string& str) {
        size_t end = str.find('\0');
        if (end != std::string::npos) {
            return str.substr(0, end);
        }
        return str;
    }

public:
    RingLWECrypto(int poly_degree = 512, int modulus = 4096)
        : poly_degree(poly_degree), q(modulus), key_gen(std::make_unique<KeyGenerator>(poly_degree, modulus)) {
        Logger::log("Initializing RingLWECrypto with polynomial degree " + std::to_string(poly_degree) + " and modulus " + std::to_string(modulus), Logger::Debug);
        secret_key = key_gen->generate_secret_key();
        public_key = key_gen->generate_public_key(secret_key);
        Logger::log("RingLWECrypto initialized successfully.", Logger::Info);
    }

    std::pair<Eigen::VectorXi, Eigen::VectorXi> encrypt(const std::string& plaintext) {
        try {
            std::cout << "poly_degree: " << poly_degree << std::endl;
            Eigen::VectorXi m = Eigen::VectorXi::Zero(poly_degree);
            std::cout << "Vector m initialized with size: " << m.size() << std::endl;
            for (size_t i = 0; i < plaintext.size() && i < poly_degree; ++i) {
                m[i] = static_cast<int>(plaintext[i]);
            }
            pad_vector(m, plaintext.size());
            Logger::log("Plaintext vector: " + vector_to_string(m), Logger::Debug);

            // Log the random vectors e1, e2, and u
            Eigen::VectorXi e1 = key_gen->generate_random_vector(poly_degree);
            Logger::log("Random vector (e1): " + vector_to_string(e1), Logger::Debug);

            Eigen::VectorXi e2 = key_gen->generate_random_vector(poly_degree);
            Logger::log("Random vector (e2): " + vector_to_string(e2), Logger::Debug);

            Eigen::VectorXi u = key_gen->generate_random_vector(poly_degree);
            Logger::log("Random vector (u): " + vector_to_string(u), Logger::Debug);

            Eigen::VectorXi c1 = key_gen->polynomial_multiply(public_key.first, u) + e1;
            Eigen::VectorXi c2 = key_gen->polynomial_multiply(public_key.second, u) + e2 + m;

            // Modulate the ciphertext components
            c1 = modulate_vector(c1, q);
            c2 = modulate_vector(c2, q);
            
            // Log the public keys
            Logger::log("Public key (a): " + vector_to_string(public_key.first), Logger::Debug);
            Logger::log("Public key (b): " + vector_to_string(public_key.second), Logger::Debug);

            // Log the ciphertext components c1 and c2
            Logger::log("Ciphertext c1: " + vector_to_string(c1), Logger::Debug);
            Logger::log("Ciphertext c2: " + vector_to_string(c2), Logger::Debug);

            // Log the ciphertext components c1 and c2
            Logger::log("Ciphertext c1: " + vector_to_string(c1), Logger::Debug);
            Logger::log("Ciphertext c2: " + vector_to_string(c2), Logger::Debug);
            Logger::log("Encryption completed successfully.", Logger::Info);

            return {c1, c2};
        } catch (const std::exception& e) {
            Logger::log("Encryption failed: " + std::string(e.what()), Logger::Error);
            throw;
        }
    }


    std::string decrypt(const std::pair<Eigen::VectorXi, Eigen::VectorXi>& ciphertext) {
        try {
            Eigen::VectorXi c1 = ciphertext.first;
            Eigen::VectorXi c2 = ciphertext.second;

            Logger::log("Decryption started.", Logger::Debug);
            Logger::log("Ciphertext c1: " + vector_to_string(c1), Logger::Debug);
            Logger::log("Ciphertext c2: " + vector_to_string(c2), Logger::Debug);

            // Decrypt the message
            Eigen::VectorXi m = key_gen->polynomial_multiply(c1, secret_key);

            Logger::log("After Multiplication m: " + vector_to_string(m), Logger::Debug);

            m = c2 - m;
            Logger::log("Before Modulation m: " + vector_to_string(m), Logger::Debug);
            m = modulate_vector(m, q);
            Logger::log("After Modulation m: " + vector_to_string(m), Logger::Debug);

            // Convert the decrypted vector to a string
            std::string plaintext;
            for (int i = 0; i < poly_degree; ++i) {
                plaintext += normalize_char(m[i]);
            }

            // Remove padding
            Logger::log("Decrypted plaintext (before padding removal): " + plaintext, Logger::Debug);
            plaintext = remove_padding(plaintext);

            Logger::log("Decrypted plaintext: " + plaintext, Logger::Info);
            return plaintext;
        } catch (const std::exception& e) {
            Logger::log("Decryption failed: " + std::string(e.what()), Logger::Error);
            throw; // Rethrow the exception after logging
        }
    }
};

} // namespace lattice_crypto

int main() {
    lattice_crypto::Logger::log("Main function started.", lattice_crypto::Logger::Debug);
    std::thread logger_thread(lattice_crypto::Logger::worker);

    try {
        lattice_crypto::RingLWECrypto crypto(512, 4096);
        std::string plaintext = "Hello, Ring-LWE!";

        auto ciphertext = crypto.encrypt(plaintext);
        std::cout << "Encrypted: " << ciphertext.first.transpose() << ", " << ciphertext.second.transpose() << std::endl;

        std::string decrypted_text = crypto.decrypt(ciphertext);
        std::cout << "Decrypted text: " << decrypted_text << std::endl;

        if (plaintext != decrypted_text) {
            lattice_crypto::Logger::log("Decryption failed: plaintext and decrypted text do not match.", lattice_crypto::Logger::Error);
            std::cerr << "Decryption failed: plaintext and decrypted text do not match." << std::endl;
            return 1; // Indicate failure
        }

        lattice_crypto::Logger::log("Encryption and decryption completed successfully.", lattice_crypto::Logger::Info);
    } catch (const std::exception& e) {
        lattice_crypto::Logger::log("An error occurred: " + std::string(e.what()), lattice_crypto::Logger::Error);
    }

    lattice_crypto::Logger::finished = true;
    lattice_crypto::Logger::cv.notify_one();
    logger_thread.join();

    lattice_crypto::Logger::log("Main function completed.", lattice_crypto::Logger::Info);
    return 0; // Indicate success
}