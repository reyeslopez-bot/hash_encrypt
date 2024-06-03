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

namespace lattice_crypto {

    namespace ntt_utils {
        void ntt(std::vector<std::complex<double>>& vec, bool inverse, int q) {
            int n = vec.size();
            int log_n = std::log2(n);
            std::vector<std::complex<double>> roots(n);

            std::complex<double> root_of_unity = std::polar(1.0, 2 * M_PI / n);
            if (inverse) {
                root_of_unity = std::polar(1.0, -2 * M_PI / n);
            }

            roots[0] = 1;
            for (int i = 1; i < n; ++i) {
                roots[i] = roots[i - 1] * root_of_unity;
            }

            for (int i = 0, j = 0; i < n; ++i) {
                if (i < j) {
                    std::swap(vec[i], vec[j]);
                }
                int bit = n >> 1;
                while (j & bit) {
                    j ^= bit;
                    bit >>= 1;
                }
                j ^= bit;
            }

            for (int len = 2; len <= n; len <<= 1) {
                int half_len = len >> 1;
                int root_step = n / len;
                for (int i = 0; i < n; i += len) {
                    for (int j = 0; j < half_len; ++j) {
                        std::complex<double> u = vec[i + j];
                        std::complex<double> v = vec[i + j + half_len] * roots[j * root_step];
                        vec[i + j] = u + v;
                        vec[i + j + half_len] = u - v;
                    }
                }
            }

            if (inverse) {
                for (int i = 0; i < n; ++i) {
                    vec[i] /= n;
                }
            }
        }
    }

    std::string matrix_to_string(const Eigen::MatrixXi& mat) {
        std::stringstream ss;
        ss << mat;
        return ss.str();
    }

    class Logger {
    public:
        enum Level { Debug, Info, Warning, Error, Fatal, Verbose };
        static std::queue<std::pair<std::string, Level>> logQueue;
        static std::mutex mtx;
        static std::condition_variable cv;
        static std::atomic<bool> finished;
        static std::ofstream logFile;
        static Level currentLogLevel;

        static void initialize(const std::string& filePath, Level logLevel = Info) {
            logFile.open(filePath, std::ios::out | std::ios::app);
            if (!logFile.is_open()) {
                throw std::runtime_error("Failed to open log file: " + filePath);
            }
            currentLogLevel = logLevel;
        }

        static void log(const std::string& message, Level level, const char* file, int line, const char* func) {
            if (level < currentLogLevel) return;
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

    std::queue<std::pair<std::string, Logger::Level>> Logger::logQueue;
    std::mutex Logger::mtx;
    std::condition_variable Logger::cv;
    std::atomic<bool> Logger::finished = false;
    std::ofstream Logger::logFile;
    Logger::Level Logger::currentLogLevel = Logger::Info;

    class KeyGenerator {
    private:
        std::mt19937 gen;
        std::uniform_int_distribution<> dist;

    public:
        KeyGenerator();

        Eigen::MatrixXi generate_random_matrix(int rows, int cols);
        Eigen::MatrixXi polynomial_multiply(const Eigen::MatrixXi& a, const Eigen::MatrixXi& b, int q);
        std::pair<Eigen::MatrixXi, Eigen::MatrixXi> generate_keys(int rows, int cols, int q);
    };

    class RingLWECrypto {
    public:
        RingLWECrypto(int poly_degree = 512, int modulus = 4096);
        ~RingLWECrypto();

        std::pair<Eigen::MatrixXi, Eigen::MatrixXi> encrypt(const std::string& plaintext);
        std::string decrypt(const std::pair<Eigen::MatrixXi, Eigen::MatrixXi>& ciphertext);

    private:
        int poly_degree;
        int q;
        std::unique_ptr<KeyGenerator> key_gen;
        std::mt19937 gen;
        Eigen::MatrixXi secret_key;
        std::pair<Eigen::MatrixXi, Eigen::MatrixXi> public_key;

        char normalize_char(int val);
        void pad_matrix(Eigen::MatrixXi& mat, int rows, int cols, int pad_val = 0);
        std::string remove_padding(const std::string& str);
        Eigen::MatrixXi modulate_matrix(const Eigen::MatrixXi& mat, int mod);
    };
}

lattice_crypto::KeyGenerator::KeyGenerator() : dist(0, 1) {
    std::random_device rd;
    gen.seed(rd());
}

Eigen::MatrixXi lattice_crypto::KeyGenerator::generate_random_matrix(int rows, int cols) {
    Eigen::MatrixXi mat(rows, cols);
    for (int i = 0; i < rows; ++i) {
        for (int j = 0; j < cols; ++j) {
            mat(i, j) = dist(gen);
        }
    }
    return mat;
}

Eigen::MatrixXi lattice_crypto::KeyGenerator::polynomial_multiply(const Eigen::MatrixXi& a, const Eigen::MatrixXi& b, int q) {
    if (a.cols() != b.rows()) {
        throw std::runtime_error("Matrix dimensions are not compatible for multiplication.");
    }

    int resultSize = 1;
    while (resultSize < a.cols() + b.rows() - 1) {
        resultSize *= 2;
    }

    std::vector<std::complex<double>> a_complex(resultSize, 0), b_complex(resultSize, 0);
    for (int i = 0; i < a.cols(); ++i) {
        a_complex[i] = std::complex<double>(a(0, i), 0);
    }
    for (int i = 0; i < b.rows(); ++i) {
        b_complex[i] = std::complex<double>(b(i, 0), 0);
    }

    lattice_crypto::ntt_utils::ntt(a_complex, false, q);
    lattice_crypto::ntt_utils::ntt(b_complex, false, q);

    std::vector<std::complex<double>> result_complex(resultSize);
    for (int i = 0; i < resultSize; ++i) {
        result_complex[i] = a_complex[i] * b_complex[i];
    }

    lattice_crypto::Logger::log("Performing inverse NTT on result_complex", lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);
    lattice_crypto::ntt_utils::ntt(result_complex, true, q);

    Eigen::MatrixXi result_int(a.rows(), b.cols());
    for (int i = 0; i < a.rows(); ++i) {
        for (int j = 0; j < b.cols(); ++j) {
            result_int(i, j) = static_cast<int>(std::round(result_complex[i + j].real() / resultSize)) % q;
        }
    }
    lattice_crypto::Logger::log("Polynomial multiplication result: " + lattice_crypto::matrix_to_string(result_int), lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);
    return result_int;
}

std::pair<Eigen::MatrixXi, Eigen::MatrixXi> lattice_crypto::KeyGenerator::generate_keys(int rows, int cols, int q) {
    lattice_crypto::Logger::log("Generating secret key", lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);
    Eigen::MatrixXi secret_key = generate_random_matrix(rows, cols);
    lattice_crypto::Logger::log("Secret key generated: " + lattice_crypto::matrix_to_string(secret_key), lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);

    lattice_crypto::Logger::log("Generating public key", lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);
    Eigen::MatrixXi public_key = polynomial_multiply(secret_key, generate_random_matrix(cols, cols), q);
    lattice_crypto::Logger::log("Public key generated: " + lattice_crypto::matrix_to_string(public_key), lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);

    return {secret_key, public_key};
}

lattice_crypto::RingLWECrypto::RingLWECrypto(int poly_degree, int modulus)
    : poly_degree(poly_degree), q(modulus), key_gen(std::make_unique<lattice_crypto::KeyGenerator>()), gen(std::random_device{}()) {

    lattice_crypto::Logger::log("Initializing RingLWECrypto with degree " + std::to_string(poly_degree)
                + " and modulus " + std::to_string(modulus) + "...", lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);

    try {
        lattice_crypto::Logger::log("Generating secret key", lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);
        secret_key = key_gen->generate_random_matrix(poly_degree, poly_degree);
        lattice_crypto::Logger::log("Secret key generated: " + lattice_crypto::matrix_to_string(secret_key), lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);

        lattice_crypto::Logger::log("Generating public key", lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);
        public_key = key_gen->generate_keys(poly_degree, poly_degree, q);
        lattice_crypto::Logger::log("Public key generated: " + lattice_crypto::matrix_to_string(public_key.first) + ", " + lattice_crypto::matrix_to_string(public_key.second), lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);

        assert(public_key.second.rows() == poly_degree && public_key.second.cols() == poly_degree);
        lattice_crypto::Logger::log("RingLWECrypto initialized successfully.", lattice_crypto::Logger::Info, __FILE__, __LINE__, __func__);
    } catch (const std::exception& e) {
        lattice_crypto::Logger::log("Initialization failed: " + std::string(e.what()), lattice_crypto::Logger::Error, __FILE__, __LINE__, __func__);
        throw;
    }
}

lattice_crypto::RingLWECrypto::~RingLWECrypto() {
    lattice_crypto::Logger::log("Destroying RingLWECrypto...", lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);
}

std::pair<Eigen::MatrixXi, Eigen::MatrixXi> lattice_crypto::RingLWECrypto::encrypt(const std::string& plaintext) {
    try {
        lattice_crypto::Logger::log("Encrypting plaintext: " + plaintext, lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);
        Eigen::MatrixXi plaintext_matrix(1, poly_degree);
        for (int i = 0; i < plaintext.size(); ++i) {
            plaintext_matrix(0, i) = static_cast<int>(plaintext[i]);
        }

        if (plaintext.size() < poly_degree) {
            for (int i = plaintext.size(); i < poly_degree; ++i) {
                plaintext_matrix(0, i) = 0;
            }
        }  
        lattice_crypto::Logger::log("Plaintext matrix: " + lattice_crypto::matrix_to_string(plaintext_matrix), lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);

        Eigen::MatrixXi error_matrix = key_gen->generate_random_matrix(1, poly_degree);
        lattice_crypto::Logger::log("Error matrix: " + lattice_crypto::matrix_to_string(error_matrix), lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);

        Eigen::MatrixXi c1 = key_gen->polynomial_multiply(public_key.first, plaintext_matrix.transpose(), q).transpose();
        Eigen::MatrixXi c2 = plaintext_matrix + key_gen->polynomial_multiply(public_key.second, error_matrix.transpose(), q).transpose();

        lattice_crypto::Logger::log("Ciphertext c1: " + lattice_crypto::matrix_to_string(c1), lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);
        lattice_crypto::Logger::log("Ciphertext c2: " + lattice_crypto::matrix_to_string(c2), lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);
        
        return {c1, c2};
    } catch (const std::exception& e) {
        lattice_crypto::Logger::log("Encryption failed: " + std::string(e.what()), lattice_crypto::Logger::Error, __FILE__, __LINE__, __func__);
        throw;
    }
}

std::string lattice_crypto::RingLWECrypto::decrypt(const std::pair<Eigen::MatrixXi, Eigen::MatrixXi>& ciphertext) {
    try {
        Eigen::MatrixXi c1 = ciphertext.first;
        Eigen::MatrixXi c2 = ciphertext.second;

        lattice_crypto::Logger::log("Decryption started.", lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);
        lattice_crypto::Logger::log("Ciphertext c1: " + lattice_crypto::matrix_to_string(c1), lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);
        lattice_crypto::Logger::log("Ciphertext c2: " + lattice_crypto::matrix_to_string(c2), lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);

        Eigen::MatrixXi m = key_gen->polynomial_multiply(c1, secret_key, q);

        lattice_crypto::Logger::log("After Multiplication m: " + lattice_crypto::matrix_to_string(m), lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);

        m = c2 - m;
        lattice_crypto::Logger::log("Before Modulation m: " + lattice_crypto::matrix_to_string(m), lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);
        m = modulate_matrix(m, q);
        lattice_crypto::Logger::log("After Modulation m: " + lattice_crypto::matrix_to_string(m), lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);

        std::string plaintext;
        for (int i = 0; i < m.cols(); ++i) {
            plaintext += normalize_char(m(0, i));
        }

        lattice_crypto::Logger::log("Decrypted plaintext (before padding removal): " + plaintext, lattice_crypto::Logger::Debug, __FILE__, __LINE__, __func__);
        plaintext = remove_padding(plaintext);

        lattice_crypto::Logger::log("Decrypted plaintext: " + plaintext, lattice_crypto::Logger::Info, __FILE__, __LINE__, __func__);
        return plaintext;
    } catch (const std::exception& e) {
        lattice_crypto::Logger::log("Decryption failed: " + std::string(e.what()), lattice_crypto::Logger::Error, __FILE__, __LINE__, __func__);
        throw;
    }
}

char lattice_crypto::RingLWECrypto::normalize_char(int val) {
    val = ((val % 256) + 256) % 256;
    if (val < 32 || val > 126) {
        return '?';
    }
    return static_cast<char>(val);
}

void lattice_crypto::RingLWECrypto::pad_matrix(Eigen::MatrixXi& mat, int rows, int cols, int pad_val) {
    for (int i = 0; i < rows; ++i) {
        for (int j = 0; j < cols; ++j) {
            if (i * cols + j >= mat.size()) {
                mat(i, j) = pad_val;
            }
        }
    }
}

std::string lattice_crypto::RingLWECrypto::remove_padding(const std::string& str) {
    size_t end = str.find_first_of('?');
    if (end != std::string::npos) {
        return str.substr(0, end);
    }
    return str;
}

Eigen::MatrixXi lattice_crypto::RingLWECrypto::modulate_matrix(const Eigen::MatrixXi& mat, int mod) {
    return mat.unaryExpr([mod](int x) { return ((x % mod) + mod) % mod; });
}

int main() {
    using namespace lattice_crypto;

    Logger::initialize("log.txt", Logger::Error);
    std::thread logger_thread(Logger::worker);

    try {
        RingLWECrypto crypt(512, 4096);
        std::string plaintext = "Hello, Ring-LWE!";
        std::cout << "Plaintext: " << plaintext << std::endl;
        
        auto ciphertext = crypt.encrypt(plaintext);
        
        // Display encrypted text
        std::cout << "Encrypted text (c1): " << matrix_to_string(ciphertext.first) << std::endl;
        std::cout << "Encrypted text (c2): " << matrix_to_string(ciphertext.second) << std::endl;

        
        std::string decrypted_text = crypt.decrypt(ciphertext);

        std::cout << "Decrypted text: " << decrypted_text << std::endl;

        if (plaintext != decrypted_text) {
            Logger::log("Decryption failed: plaintext and decrypted text do not match.", Logger::Error, __FILE__, __LINE__, __func__);
            std::cerr << "Decryption failed: plaintext and decrypted text do not match." << std::endl;
            return 1;
        }

        Logger::log("Encryption and decryption completed successfully.", Logger::Info, __FILE__, __LINE__, __func__);

        Logger::finished = true;
        Logger::cv.notify_one();

        Logger::log("Application is shutting down", Logger::Info, __FILE__, __LINE__, __func__);
    } catch (const std::exception& e) {
        Logger::log("An error occurred: " + std::string(e.what()), Logger::Error, __FILE__, __LINE__, __func__);
        std::cerr << "Exception occurred: " << e.what() << std::endl;
    }

    logger_thread.join();
    Logger::finalize();
    return EXIT_SUCCESS;
}
