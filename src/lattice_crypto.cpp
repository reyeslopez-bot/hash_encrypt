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
#include <boost/lockfree/queue.hpp>

// Function to convert an Eigen vector to a string
std::string vector_to_string(const Eigen::VectorXi& vec) {
    std::stringstream ss;
    ss << vec.transpose();
    return ss.str();
}

namespace lattice_crypto {

    class Logger {
    public:
        enum Level { Debug, Info, Warning, Error, Fatal, Verbose };
        static std::queue<std::pair<std::string, Level>> logQueue;
        static std::mutex mtx;
        static std::condition_variable cv;
        static std::atomic<bool> finished;
        static std::ofstream logFile;

        static void initialize(const std::string& filePath) {
            logFile.open(filePath, std::ios::out | std::ios::app);
            if (!logFile.is_open()) {
                throw std::runtime_error("Failed to open log file: " + filePath);
            }
        }

        static void log(const std::string& message, Level level, const char* file, int line, const char* func) {
            std::lock_guard<std::mutex> lock(mtx);
            auto now = std::chrono::system_clock::now();
            auto now_time = std::chrono::system_clock::to_time_t(now);
            std::ostringstream oss;
            oss << std::put_time(std::localtime(&now_time), "%Y-%m-%d %H:%M:%S");
            oss << " [" << std::this_thread::get_id() << "]";
            oss << " " << file << ":" << func << ":" << line << " - ";
            switch (level) {
                case Debug: oss << "DEBUG: "; break;
                case Info: oss << "INFO: "; break;
                case Warning: oss << "WARNING: "; break;
                case Error: oss << "ERROR: "; break;
                case Fatal: oss << "FATAL: "; break;
                case Verbose: oss << "VERBOSE: "; break;
            }
            oss << message;
            logQueue.push(std::make_pair(oss.str(), level));
            cv.notify_one();
        }

        static void worker() {
            std::pair<std::string, Level> log;
            while (!finished) {
                {
                    std::unique_lock<std::mutex> lock(mtx);
                    cv.wait(lock, [] { return !logQueue.empty() || finished; });
                }
                while (!logQueue.empty()) {
                    std::lock_guard<std::mutex> lock(mtx);
                    log = logQueue.front();
                    logQueue.pop();
                    if (logFile.is_open()) {
                        logFile << log.first << std::endl;
                    }
                    std::cout << log.first << std::endl;
                }
            }
        }

        static void finalize() {
            finished = true;
            cv.notify_one();
            if (logFile.is_open()) {
                logFile.close();
            }
        }
    };
    // Initialize static members
    std::queue<std::pair<std::string, lattice_crypto::Logger::Level>> lattice_crypto::Logger::logQueue;
    std::mutex lattice_crypto::Logger::mtx;
    std::condition_variable lattice_crypto::Logger::cv;
    std::atomic<bool> lattice_crypto::Logger::finished = false;
    std::ofstream lattice_crypto::Logger::logFile;  // Definition
    // KeyGenerator class for generating Ring-LWE keys
    class KeyGenerator {
    private:
        int poly_degree;
        int q;
        std::mt19937 gen{std::random_device{}()};
        std::uniform_int_distribution<> dist;

    public:
        KeyGenerator(int poly_degree, int modulus)
        : poly_degree(poly_degree), q(modulus), gen(std::random_device{}()), dist(-q/2, q/2) {
            lattice_crypto::Logger::log("KeyGenerator initialized with polynomial degree and modulus.", lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);
        }
        static inline int modulo(int x, int m) {
            return (x % m + m) % m;
        }

        Eigen::MatrixXi generate_secret_key() {
            Eigen::MatrixXi secret_key = generate_random_matrix(poly_degree, poly_degree);
            lattice_crypto::Logger::log("Secret key generated successfully.", lattice_crypto::Logger::Info, __FILE__, __LINE__, __func__);
            lattice_crypto::Logger::log("Secret key: " + vector_to_string(secret_key), lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);
            return secret_key;
        }

        std::pair<Eigen::MatrixXi, Eigen::MatrixXi> generate_public_key(const Eigen::MatrixXi& secret_key) {
            Eigen::MatrixXi a = generate_random_matrix(poly_degree, poly_degree);
            Eigen::MatrixXi e = generate_random_matrix(poly_degree, poly_degree);
            Eigen::MatrixXi b = polynomial_multiply(a, secret_key) + e;
            b = b.unaryExpr([this](int x) { return ((x % q) + q) % q; });
            lattice_crypto::Logger::log("Public key generated successfully.", lattice_crypto::Logger::Info, __FILE__, __LINE__, __func__);
            return {a, b};
        }

        Eigen::MatrixXi generate_random_matrix(int rows, int cols) {
            Eigen::MatrixXi mat(rows, cols);
            for (int i = 0; i < rows; ++i) {
                for (int j = 0; j < cols; ++j) {
                    mat(i, j) = dist(gen);
                }
            }
            return mat;
        }

    Eigen::MatrixXi polynomial_multiply(const Eigen::MatrixXi& a, const Eigen::MatrixXi& b) {
        Eigen::FFT<double> fft;
        std::vector<std::complex<double>> a_complex(a.size()), b_complex(b.size());
        Eigen::MatrixXi result_int(a.rows(), b.cols());

        try {
            // Initialize complex vectors from integer matrices
            for (int i = 0; i < a.rows(); ++i) {
                for (int j = 0; j < a.cols(); ++j) {
                    a_complex[i * a.cols() + j] = std::complex<double>(a(i, j), 0);
                    b_complex[i * b.cols() + j] = std::complex<double>(b(i, j), 0);
                }
            }

            fft.fwd(a_complex, a_complex);
            fft.fwd(b_complex, b_complex);

            std::vector<std::complex<double>> result_complex(a_complex.size());
            for (size_t i = 0; i < a_complex.size(); ++i) {
                result_complex[i] = a_complex[i] * b_complex[i];
            }

            fft.inv(result_complex, result_complex);
            for (size_t i = 0; i < result_complex.size(); ++i) {
                int row = i / a.cols();
                int col = i % a.cols();
                result_int(row, col) = modulo(std::lround(result_complex[i].real()), q);
            }
        } catch (const std::overflow_error& e) {
            lattice_crypto::Logger::log("Overflow error in polynomial multiply: " + std::string(e.what()), lattice_crypto::Logger::Error, __FILE__, __LINE__, __func__);
            throw;
        } catch (const std::runtime_error& e) {
            lattice_crypto::Logger::log("Runtime error in polynomial multiply: " + std::string(e.what()), lattice_crypto::Logger::Error, __FILE__, __LINE__, __func__);
            throw;
        } catch (const std::exception& e) {
            lattice_crypto::Logger::log("Exception in polynomial_multiply: " + std::string(e.what()), lattice_crypto::Logger::Error, __FILE__, __LINE__, __func__);
            throw;
        }

        return result_int;
    }
        };

    class RingLWECrypto {
    public:
        RingLWECrypto(int poly_degree = 512, int modulus = 4096) : poly_degree(poly_degree), q(modulus),
            key_gen(std::make_unique<KeyGenerator>(poly_degree, modulus)), gen(std::random_device{}()) {
            Logger::log("Initializing RingLWECrypto...", Logger::Debug, __FILE__, __LINE__, __func__);
            secret_key = key_gen->generate_secret_key();
            public_key = key_gen->generate_public_key(secret_key);
            assert(public_key.second.rows() == poly_degree && public_key.second.cols() == poly_degree);  // Now correctly placed in constructor
        }
        std::pair<Eigen::MatrixXi, Eigen::MatrixXi> encrypt(const std::string& plaintext);
        std::string decrypt(const std::pair<Eigen::MatrixXi, Eigen::MatrixXi>& ciphertext);

    private:
        int poly_degree;
        int q;
        Eigen::MatrixXi secret_key;
        std::pair<Eigen::MatrixXi, Eigen::MatrixXi> public_key;
        std::unique_ptr<KeyGenerator> key_gen;
        std::mt19937 gen;
    

        char normalize_char(int val) {
            val = ((val % 256) + 256) % 256;
            if (val < 32 || val > 126) {
                return '?'; // Non-printable characters are replaced with '?'
            }
            return static_cast<char>(val);
        }

        void pad_matrix(Eigen::MatrixXi& mat, int rows, int cols, int pad_val = 0) {
            for (int i = 0; i < rows; ++i) {
                for (int j = 0; j < cols; ++j) {
                    if (i * cols + j >= mat.size()) {
                        mat(i, j) = pad_val;
                    }
                }
            }
        }

        std::string remove_padding(const std::string& str) {
            size_t end = str.find('\0');
            if (end != std::string::npos) {
                return str.substr(0, end);
            }
            return str;
        }
        
        Eigen::MatrixXi modulate_matrix(const Eigen::MatrixXi& mat, int mod) {
            return mat.unaryExpr([mod](int x) { return ((x % mod) + mod) % mod; });
        }
    };

    std::pair<Eigen::MatrixXi, Eigen::MatrixXi> RingLWECrypto::encrypt(const std::string& plaintext) {
        try {
            std::cout << "poly_degree: " << poly_degree << std::endl;
            Eigen::MatrixXi m = Eigen::MatrixXi::Zero(poly_degree, poly_degree);
            std::cout << "Matrix m initialized with size: " << m.size() << std::endl;
            for (int i = 0; i < plaintext.size() && i < poly_degree * poly_degree; ++i) {
                m(i / poly_degree, i % poly_degree) = static_cast<int>(plaintext[i]);
            }
            pad_matrix(m, poly_degree, poly_degree);
            lattice_crypto::Logger::log("Plaintext matrix: " + vector_to_string(m), lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);

            // Log the random matrices e1, e2, and u
            Eigen::MatrixXi e1 = key_gen->generate_random_matrix(poly_degree, poly_degree);
            lattice_crypto::Logger::log("Random matrix (e1): " + vector_to_string(e1), lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);

            Eigen::MatrixXi e2 = key_gen->generate_random_matrix(poly_degree, poly_degree);
            lattice_crypto::Logger::log("Random matrix (e2): " + vector_to_string(e2), lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);

            Eigen::MatrixXi u = key_gen->generate_random_matrix(poly_degree, poly_degree);
            lattice_crypto::Logger::log("Random matrix (u): " + vector_to_string(u), lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);

            Eigen::MatrixXi c1 = key_gen->polynomial_multiply(public_key.first, u) + e1;
            Eigen::MatrixXi c2 = key_gen->polynomial_multiply(public_key.second, u) + e2 + m;

            // Modulate the ciphertext components
            c1 = modulate_matrix(c1, q);
            c2 = modulate_matrix(c2, q);
            
            // Log the public keys
            lattice_crypto::Logger::log("Public key (a): " + vector_to_string(public_key.first), lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);
            lattice_crypto::Logger::log("Public key (b): " + vector_to_string(public_key.second), lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);

            // Log the ciphertext components c1 and c2
            lattice_crypto::Logger::log("Ciphertext c1: " + vector_to_string(c1), lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);
            lattice_crypto::Logger::log("Ciphertext c2: " + vector_to_string(c2), lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);
            lattice_crypto::Logger::log("Encryption completed successfully.", lattice_crypto::Logger::Info, __FILE__, __LINE__, __func__);

            return {c1, c2};
        } catch (const std::exception& e) {
            lattice_crypto::Logger::log("Encryption failed: " + std::string(e.what()), lattice_crypto::Logger::Error, __FILE__, __LINE__, __func__);
            throw;
        }
    }

    std::string RingLWECrypto::decrypt(const std::pair<Eigen::MatrixXi, Eigen::MatrixXi>& ciphertext) {
        try {
            Eigen::MatrixXi c1 = ciphertext.first;
            Eigen::MatrixXi c2 = ciphertext.second;

            lattice_crypto::Logger::log("Decryption started.", lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);
            lattice_crypto::Logger::log("Ciphertext c1: " + vector_to_string(c1), lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);
            lattice_crypto::Logger::log("Ciphertext c2: " + vector_to_string(c2), lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);

            // Decrypt the message
            Eigen::MatrixXi m = key_gen->polynomial_multiply(c1, secret_key);

            lattice_crypto::Logger::log("After Multiplication m: " + vector_to_string(m), lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);

            m = c2 - m;
            lattice_crypto::Logger::log("Before Modulation m: " + vector_to_string(m), lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);
            m = modulate_matrix(m, q);
            lattice_crypto::Logger::log("After Modulation m: " + vector_to_string(m), lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);

            // Convert the decrypted matrix to a string
            std::string plaintext;
            for (int i = 0; i < poly_degree * poly_degree; ++i) {
                plaintext += normalize_char(m(i / poly_degree, i % poly_degree));
            }

            // Remove padding
            lattice_crypto::Logger::log("Decrypted plaintext (before padding removal): " + plaintext, lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);
            plaintext = remove_padding(plaintext);

            lattice_crypto::Logger::log("Decrypted plaintext: " + plaintext, lattice_crypto::Logger::Info, __FILE__, __LINE__, __func__);
            return plaintext;
        } catch (const std::exception& e) {
            lattice_crypto::Logger::log("Decryption failed: " + std::string(e.what()), lattice_crypto::Logger::Error, __FILE__, __LINE__, __func__);
            throw; // Rethrow the exception after logging
        }
    }

} // namespace lattice_crypto

int main() {
    // Initialize```cpp
    // Initialize the logger
    lattice_crypto::Logger::initialize("log.txt");
    std::thread logger_thread(lattice_crypto::Logger::worker);

    try {
        lattice_crypto::RingLWECrypto crypto(512, 4096);
        std::string plaintext = "Hello, Ring-LWE!";

        auto ciphertext = crypto.encrypt(plaintext);
        std::string decrypted_text = crypto.decrypt(ciphertext);
        
        std::cout << "Decrypted text: " << decrypted_text << std::endl;

        if (plaintext != decrypted_text) {
            lattice_crypto::Logger::log("Decryption failed: plaintext and decrypted text do not match.", lattice_crypto::Logger::Error, __FILE__, __LINE__, __func__);
            std::cerr << "Decryption failed: plaintext and decrypted text do not match." << std::endl;
            return 1; // Indicate failure
        }

        lattice_crypto::Logger::log("Encryption and decryption completed successfully.", lattice_crypto::Logger::Info, __FILE__, __LINE__, __func__);
        
        // Notify logger that processing is done
        lattice_crypto::Logger::finished = true;
        lattice_crypto::Logger::cv.notify_one();

        // Log shutdown message
        lattice_crypto::Logger::log("Application is shutting down", lattice_crypto::Logger::Info, __FILE__, __LINE__, __func__);
    } catch (const std::exception& e) {
        lattice_crypto::Logger::log("An error occurred: " + std::string(e.what()), lattice_crypto::Logger::Error, __FILE__, __LINE__, __func__);
        std::cerr << "Exception occurred: " << e.what() << std::endl;
    }

    // Wait for the logger thread to finish
    logger_thread.join();

    // Finalize the logger properly
    lattice_crypto::Logger::finalize();

    return EXIT_SUCCESS;
}
