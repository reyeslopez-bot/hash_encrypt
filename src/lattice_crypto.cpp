#include <iostream> //iostream: Enables basic input and output operations
#include <vector> //vector:Provides dynamic array functionality
#include <cmath> //cmath: Mathematical functions  (e.g., std::abs for absolute value)
#include <cstdlib> //cstdlib:  Includes standard C library functions. Primarily, you're using std::rand and std::srand for random number generation.
#include <ctime> //ctime: Provides functions for working with time, used to seed your random number generator. C-style time/date utilities
#include <stdexcept> //stdexcept: Includes standard exception classes in C++ (like std::runtime_error which you might use for error handling).
#include <Eigen/Dense> //Eigen:  C++ The core dependency for linear algebra operations. The Eigen library is used heavily for matrix manipulations.
#include <exception> //exception: Standard exceptions. Includes additional exception classes, used for refined error handling
#include <string> //string:  Includes the std::string class, used for string manipulation.
#include <iomanip> //iomanip:  Provides tools for controlling the format of input and output operations.
#include <fstream> //fstream:  Provides tools for file input and output operations.
#include <sstream> //sstream:  Provides tools for string stream operations.
#include <algorithm> //algorithm:  Provides a collection of functions for working with sequences of elements, used for sorting.
#include <numeric> //numeric:  Provides a collection of functions for numeric operations, used for accumulating values.
#include <functional> //functional:  Provides tools for working with function objects, used for defining custom functions.
#include <random> //random:  Provides tools for generating random numbers, used for random number generation.
#include <chrono> //chrono:  Provides tools for working with time, used for measuring time durations.
#include <thread> //thread:  Provides tools for working with threads, used for multithreading.
#include <future> //future:  Provides tools for working with asynchronous operations, used for asynchronous programming.
#include <mutex> //mutex:  Provides tools for working with mutexes, used for thread synchronization.
#include <condition_variable> //condition_variable:  Provides tools for working with condition variables, used for thread synchronization.
#include <atomic> //atomic:  Provides tools for working with atomic operations, used for thread synchronization.
#include <type_traits> //type_traits:  Provides tools for working with types, used for type checking.
#include <utility> //utility:  Provides tools for working with pairs, used for key-value pairs.
#include <limits> //limits:  Provides tools for working with numeric limits, used for checking numeric limits.
#include <memory> //memory:  Provides tools for working with memory, used for memory management.
#include <tuple> //tuple:  Provides tools for working with tuples, used for grouping values.
#include <initializer_list> //initializer_list:  Provides tools for working with initializer lists, used for initializing containers.

// starts the definition of the LatticeCrypto class and declares some of its private member variables:
class LatticeCrypto {
private:
    int key_size; // The integer that will store the dimensions of the square matrices used within your cryptographic scheme
    int q; // The integer that will store the modulus used in your cryptographic scheme
    Eigen::MatrixXi secret_key; // An Eigen matrix (MatrixXi) that will hold your secret key. The 'Xi' indicates the matrix contains integer elements. variables are declared as private, ensuring they can only be directly accessed from within the LatticeCrypto class. 
    Eigen::MatrixXi public_key; // Another Eigen matrix to store your derived public key.
    // The use of Eigen's MatrixXi type signals that you'll be heavily relying on matrix operations for your cryptography implementation.

    // Helper function to calculate the modular multiplicative inverse
    int modular_multiplicative_inverse(int a, int mod) { //calculates the modular multiplicative inverse of a number a with respect to a modulus mod. This inverse is essential in certain decryption processes within lattice-based schemes. Extends the Euclidean algorithm to find the modular multiplicative inverse of a number a with respect to a modulus mod.
        int m0 = mod, t, q;
        int x0 = 0, x1 = 1;

        if (mod == 1) return 0;  // If mod is 1, there is no inverse, so 0 is returned.

        while (a > 1) { // The while loop calculates the inverse using the extended Euclidean algorithm.
            q = a / mod; // The quotient of a divided by mod is stored in q.
            t = mod; // The value of mod is stored in t.
            mod = a % mod, a = t; // The remainder of a divided by mod is stored in mod, and the value of mod is stored in a.
            t = x0; // The value of x0 is stored in t.
            x0 = x1 - q * x0; // The value of x1 minus q times x0 is stored in x0.
            x1 = t; // The value of t is stored in x1.
        }

        if (x1 < 0) x1 += m0; // Ensures the returned inverse is positive.

        return x1; // Returns the modular multiplicative inverse.
    }

#include <random>

    Eigen::MatrixXi generate_key() {
        Eigen::MatrixXi key(key_size, key_size);
        std::random_device rd;
        std::mt19937 generator(rd());
        std::normal_distribution<double> distribution(0.0, 3.0); // Adjust standard deviation as needed

        int attempt = 0;
        bool valid = false;

        while (!valid && attempt < 10) {
            for (int i = 0; i < key_size; ++i) {
                for (int j = 0; j < key_size; ++j) {
                    key(i, j) = static_cast<int>(std::round(distribution(generator)));
                }
            }

            Eigen::MatrixXd keyDouble = key.cast<double>();
            double det = keyDouble.determinant();
            int detModQ = static_cast<int>(std::round(det)) % q;

            if (std::abs(det) < 1e-9 || detModQ == 0) {
                std::cerr << "Regenerating key matrix, determinant issue." << std::endl;
                attempt++;
            } else {
                valid = true;
            }
        }

        if (!valid) {
            throw std::runtime_error("Failed to generate a valid key matrix after several attempts.");
        }

        return key;
    }

    Eigen::MatrixXi matrix_mod(const Eigen::MatrixXi& matrix, int modulus) {
        Eigen::MatrixXi modMatrix = matrix;
        for (int i = 0; i < modMatrix.rows(); i++) {
            for (int j = 0; j < modMatrix.cols(); j++) {
                modMatrix(i, j) = modMatrix(i, j) % modulus;
            }
        }
        return modMatrix;
    }

    // You'll likely need a better random number source for true security
    Eigen::MatrixXi binomial_error(const Eigen::MatrixXi& size) { // Generates a matrix representing errors, likely used to add noise during the encryption process.
        int n = size.rows() * size.cols();  // Number of samples
        double p = 0.5;  // Probability (adjust this parameter carefully)
        Eigen::MatrixXi result(size.rows(), size.cols());

        for (int i = 0; i < n; ++i) {
            int successes = 0;
            for (int j = 0; j < q/2; ++j) {  // Arbitrary number of trials
                if (std::rand() / double(RAND_MAX) < p) { // Random number in [0, 1). Not suitable for cryptographic use.
                    ++successes;
                }
            }
            // Center around zero
            result(i / size.cols(), i % size.cols()) = successes - q/4;  
        }
        return result;
    }

    Eigen::MatrixXi generate_public_key() { // Creates the public key matrix from the secret key and error matrices.
        Eigen::MatrixXi error_matrix = binomial_error(Eigen::MatrixXi::Zero(key_size, key_size)); // Generates an error matrix using the binomial_error function..
        return matrix_mod(secret_key * error_matrix + binomial_error(Eigen::MatrixXi::Zero(key_size, key_size)), q); // Takes an Eigen matrix and applies the modulus operation to each element. This keeps the values within the desired range for your cryptography.
    }

    // Two simple utility functions to convert between Eigen's integer matrix (MatrixXi) and floating-point matrix (MatrixXd) representations.
    Eigen::MatrixXi convertDoubleToInt(const Eigen::MatrixXd& matrix) {
        return matrix.cast<int>();
    }

    Eigen::MatrixXd convertIntToDouble(const Eigen::MatrixXi& matrix) {
        return matrix.cast<double>();
    }

    Eigen::MatrixXi matrix_mod_inv(const Eigen::MatrixXi& matrix, int modulus) { //  Attempts to calculate the modular inverse of a matrix. This is a potentially complex operation in lattice cryptography. Double-precision matrix is used to calculate the determinant, which is then converted back to an integer.
        Eigen::MatrixXd matrixDouble = convertIntToDouble(matrix); // Converts the input matrix to a double-precision matrix.
        double det = matrixDouble.determinant(); // Calculates the determinant of the input matrix.
        std::cout << "Determinant for inversion: " << det << std::endl; // Outputs the determinant for debugging purposes.

        if (std::abs(det) < 1e-9) { // If the determinant is too close to zero, an exception is thrown.
            throw std::invalid_argument("Matrix is singular and cannot be inverted.");
        }

        int det_int = static_cast<int>(std::round(det)) % modulus; // Converts the determinant to an integer and applies the modulus operation.
        if (det_int == 0) {
            throw std::invalid_argument("Determinant modulo is zero, no inverse exists.");
        }

        int det_mod_inv = modular_multiplicative_inverse(det_int, modulus); // Calculates the modular multiplicative inverse of the determinant.
        if (det_mod_inv == 0) {
            throw std::invalid_argument("Determinant has no modular inverse under modulus.");
        }

    Eigen::MatrixXi adj = convertDoubleToInt(matrixDouble.adjoint().eval()); // Calculates the adjoint of the input matrix and converts it back to an integer matrix.
    return (adj * det_mod_inv).unaryExpr([modulus](int x) { return ((x % modulus) + modulus) % modulus; });
}
    Eigen::MatrixXi safe_modulus(const Eigen::MatrixXd& matrix, int modulus) { // This function takes a matrix with floating-point elements (Eigen::MatrixXd) and safely applies the modulus operation to each element,
        Eigen::MatrixXi result(matrix.rows(), matrix.cols());
        for (int i = 0; i < matrix.rows(); i++) {
            for (int j = 0; j < matrix.cols(); j++) {
                double element = matrix(i, j);
                result(i, j) = static_cast<int>(std::round(element)) % modulus;
            }
        }
        return result;
    }

public:
    LatticeCrypto(int security_level = 128) { // Constructor for the LatticeCrypto class. It initializes the cryptographic parameters based on the desired security level.
        set_parameters(security_level);
        secret_key = generate_key(); // Generates the secret key matrix.
        public_key = generate_public_key(); // Generates the public key matrix.
    }

    void set_parameters(int security_level) { // Sets the cryptographic parameters based on the desired security level.
        if (security_level == 128) { // The function sets the key_size and modulus q based on the security level provided.
            key_size = 512; // The key_size is set to 512, and the modulus q is set to 4096.
            q = 4096; // Or a larger prime from a reputable source
        } else if (security_level == 256) { // If the security level is 256, the key_size is set to 1024, and the modulus q is set to 15331.
            key_size = 1024; // The key_size is set to 1024, and the modulus q is set to 15331.
            q = 15331;  // Or a larger prime from a reputable source
        } else { // If the security level is not 128 or 256, an exception is thrown.
            throw std::invalid_argument("Unsupported security level: " + std::to_string(security_level)); // The function throws an invalid_argument exception with a message indicating the unsupported security level.
        }
    }
    const Eigen::MatrixXi& getSecretKey() const { // Returns a const reference to the secret key matrix.
        return secret_key; // The function simply returns the secret_key member variable.
    }

    Eigen::MatrixXi encrypt(const std::string& plaintext) { // Encrypts a plaintext string using the public key.
        Eigen::MatrixXi plaintext_vector(key_size, 1); // The function takes a plaintext string as input and returns the encrypted ciphertext as an Eigen matrix.
        for (size_t i = 0; i < plaintext.size(); ++i) { // The function first converts the plaintext string to an Eigen matrix of integers.
            plaintext_vector(i, 0) = plaintext[i]; // The ASCII value of each character is stored in the plaintext_vector matrix.
        }

        // Compute the ciphertext
        Eigen::MatrixXi ciphertext = (public_key * plaintext_vector + binomial_error(Eigen::MatrixXi::Zero(key_size, 1))); // The function computes the ciphertext by multiplying the public key matrix with the plaintext vector and adding noise.
        ciphertext = matrix_mod(ciphertext, q); // Apply modulus after all operations

        // Debug: Print the first few encrypted values to see what's being produced
        std::cout << "Debug: Printing first few encrypted values:" << std::endl; // The function outputs the first few encrypted values for debugging purposes.
        for (int i = 0; i < std::min(5, key_size); ++i) { // The function outputs the first few encrypted values for debugging purposes.
            std::cout << ciphertext(i, 0) << " "; // The function outputs the first few encrypted values for debugging purposes.
        }
        std::cout << std::endl; // The function outputs the first few encrypted values for debugging purposes.

        return ciphertext;
    }

    std::string decrypt(const Eigen::MatrixXi& ciphertext) { // Decrypts a ciphertext matrix using the secret key.
        try {
            Eigen::MatrixXi inv_key = matrix_mod_inv(secret_key, q); // The function first calculates the modular inverse of the secret key matrix.
            std::cout << "Debug: Inverse Matrix (before applying to ciphertext):" << std::endl; // The function outputs the inverse matrix for debugging purposes.

            Eigen::MatrixXi product = inv_key * ciphertext; // The function then multiplies the inverse key matrix with the ciphertext matrix.

            Eigen::MatrixXi decrypted_vector(product.rows(), product.cols()); // The function creates a matrix to store the decrypted ASCII values.

            // Apply modulus operation element-wise, ensuring positive results
            for (int i = 0; i < product.rows(); ++i) { // The function applies the modulus operation element-wise to the product matrix.
                for (int j = 0; j < product.cols(); ++j) { // The function applies the modulus operation element-wise to the product matrix.
                    int value = product(i, j) % q; // The function applies the modulus operation element-wise to the product matrix.
                    if (value < 0) value += q;  // Ensure the result is positive
                    decrypted_vector(i, j) = value; // The function stores the result in the decrypted_vector matrix.
                }
            }

            std::string decrypted_text; // The function initializes an empty string to store the decrypted text.
            std::cout << "Debug: Decrypted ASCII values:" << std::endl; // The function outputs the decrypted ASCII values for debugging purposes.
            for (int i = 0; i < decrypted_vector.rows(); ++i) { // The function outputs the decrypted ASCII values for debugging purposes.
                int val = decrypted_vector(i, 0); // The function retrieves the ASCII value from the decrypted_vector matrix.
                val = (val % 128 + 128) % 128;  // Normalize to ASCII range
                std::cout << val << " ";  // Debug output of ASCII values
                if (val >= 32 && val < 127) { // The function checks if the ASCII value is within the printable range.
                    decrypted_text += static_cast<char>(val); // The function appends the corresponding character to the decrypted text.
                } else { // If the ASCII value is not printable, a '?' is substituted.
                    decrypted_text += '?'; // Substitute non-printable characters
                }
            }
            std::cout << std::endl; // The function outputs the decrypted ASCII values for debugging purposes.

            if (decrypted_text.empty() || decrypted_text.find('?') != std::string::npos) {
                std::cerr << "Decryption produced non-printable characters or empty result." << std::endl;
            }

            return decrypted_text;
        } catch (const std::exception& e) {
            std::cerr << "Decryption failed: " << e.what() << std::endl;
            return "Decryption Error";
        }
    }

        void print_matrix(const Eigen::MatrixXi& matrix) {
            for (int i = 0; i < matrix.rows(); i++) {
                for (int j = 0; j < matrix.cols(); j++) {
                    std::cout << matrix(i, j) << " ";
                }
                std::cout << std::endl;
            }
        }

    double norm_rand(double sigma) {
        double u = static_cast<double>(std::rand()) / RAND_MAX; // The function generates a random number u in the range [0, 1).
        double v = static_cast<double>(std::rand()) / RAND_MAX; // The function generates a random number v in the range [0, 1).
        return sigma * std::sqrt(-2.0 * std::log(u)) * std::cos(2 * M_PI * v);
    }

    void check_first_element(const Eigen::MatrixXd& matrix) { // The function checks the first element of a matrix for evenness or oddness.
        if (matrix.size() == 0) { // The function checks if the matrix is empty.
            std::cerr << "Empty matrix provided." << std::endl; // The function outputs an error message if the matrix is empty.
            return;
        }

        if (static_cast<int>(matrix(0, 0)) % 2 == 0) { // The function checks if the first element of the matrix is even.
            std::cout << "First element is even." << std::endl; // The function outputs a message indicating the first element is even.
        } else {
            std::cout << "First element is odd." << std::endl; // The function outputs a message indicating the first element is odd.
        }
    }
};

int main() { // The main function serves as the entry point for your program.
    try {
        std::srand(static_cast<unsigned int>(std::time(nullptr)));  // Seed the random number generator
        LatticeCrypto crypto;
        std::string plaintext = "Hello, world!";

        // Encrypt the plaintext
        Eigen::MatrixXi ciphertext; // The main function initializes an Eigen matrix to store the ciphertext.
        try {
            ciphertext = crypto.encrypt(plaintext);
            std::cout << "Encryption successful." << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "Encryption failed: " << e.what() << std::endl;
            return 1;
        }

        // Debug output for secret key (place it right here after encryption)
        std::cout << "Debug: Secret Key (first few rows):" << std::endl; // The main function outputs the first few rows of the secret key matrix for debugging purposes.
        for (Eigen::Index i = 0; i < std::min<Eigen::Index>(5, crypto.getSecretKey().rows()); ++i) { // The main function outputs the first few rows of the secret key matrix for debugging purposes.
            for (Eigen::Index j = 0; j < std::min<Eigen::Index>(5, crypto.getSecretKey().cols()); ++j) { // The main function outputs the first few rows of the secret key matrix for debugging purposes.
                std::cout << crypto.getSecretKey()(i, j) << " "; // The main function outputs the first few rows of the secret key matrix for debugging purposes.
            }
            std::cout << std::endl; // The main function outputs the first few rows of the secret key matrix for debugging purposes.
        }

        // Decrypt the ciphertext
        std::string decrypted_text; // The main function initializes a string to store the decrypted text.
        try {
            decrypted_text = crypto.decrypt(ciphertext); // Decrypts the ciphertext using the decrypt function.
            std::cout << "Decryption successful." << std::endl; // The main function outputs a success message if the decryption is successful.
        } catch (const std::exception& e) { // The main function catches any exceptions thrown during the cryptographic operations.
            std::cerr << "Decryption failed: " << e.what() << std::endl; // The main function outputs an error message indicating the exception that occurred.
            return 1; // The main function returns a non-zero value to indicate an error.
        }

        // Output the results
        std::cout << "Original Text: " << plaintext << std::endl;
        std::cout << "Decrypted Text: " << decrypted_text << std::endl;
        if (plaintext != decrypted_text) {
            std::cerr << "Decryption check failed. Original and decrypted texts do not match." << std::endl;
            return 1;
        }

        // Additional debug output to examine the content of the example matrix
        Eigen::MatrixXd example_matrix(1, 1);
        example_matrix(0, 0) = 4;  // Modify this value to test even/odd detection
        std::cout << "Matrix example element check initiated." << std::endl; // The function checks the first element of a matrix for evenness or oddness.
        crypto.check_first_element(example_matrix); // The function checks the first element of a matrix for evenness or oddness.
        std::cout << "Matrix element check completed." << std::endl; // The function checks the first element of a matrix for evenness or oddness.

    } catch (const std::exception& e) { // The main function catches any exceptions thrown during the cryptographic operations.
        std::cerr << "An unexpected error occurred: " << e.what() << std::endl; // The main function outputs an error message indicating the exception that occurred.
        return 1; // The main function returns a non-zero value to indicate an error.
    }

    return 0;
} // The main function returns 0 to indicate successful completion.
