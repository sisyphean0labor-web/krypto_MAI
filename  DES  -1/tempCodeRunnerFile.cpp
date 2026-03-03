#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <queue>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iomanip>
#include <random>
#include <chrono>

namespace fs = std::filesystem;

// Константы для алгоритмов
const size_t DES_BLOCK_SIZE = 8; // 64 бита
const size_t DES_KEY_SIZE = 8;   // 64 бита (с битами четности)
const size_t TRIPLE_DES_KEY_SIZE = 24; // 192 бита
const size_t DEAL_BLOCK_SIZE = 16; // 128 бит
const size_t DEAL_KEY_SIZE = 16;   // 128 бит (может быть 128/192/256, для простоты 128)

// Перечисление режимов шифрования
enum class CipherMode {
    ECB, CBC, PCBC, CFB, OFB, CTR, RANDOM_DELTA
};

// Перечисление режимов набивки
enum class PaddingMode {
    ZEROS, ANSI_X923, PKCS7, ISO_10126
};

// Перечисление алгоритмов
enum class Algorithm {
    DES, TRIPLE_DES, DEAL
};

// Базовый класс для алгоритмов шифрования
class BlockCipher {
public:
    virtual ~BlockCipher() = default;
    virtual void encrypt_block(const uint8_t* input, uint8_t* output) = 0;
    virtual void decrypt_block(const uint8_t* input, uint8_t* output) = 0;
    virtual size_t block_size() const = 0;
    virtual size_t key_size() const = 0;
};

// Реализация DES (упрощенная для демонстрации)
class DES : public BlockCipher {
private:
    // В реальной реализации здесь должны быть таблицы перестановок и S-блоки DES
    // Для демонстрации используем упрощенный XOR (небезопасно!)
    std::vector<uint8_t> key;
    
public:
    DES(const std::vector<uint8_t>& user_key) {
        key = user_key;
        if (key.size() < DES_KEY_SIZE) {
            key.resize(DES_KEY_SIZE, 0);
        } else {
            key.resize(DES_KEY_SIZE);
        }
    }
    
    void encrypt_block(const uint8_t* input, uint8_t* output) override {
        // Упрощенная имитация шифрования (только для демонстрации)
        for (size_t i = 0; i < DES_BLOCK_SIZE; ++i) {
            output[i] = input[i] ^ key[i % key.size()] ^ 0xAA;
        }
    }
    
    void decrypt_block(const uint8_t* input, uint8_t* output) override {
        // Упрощенная имитация дешифрования
        for (size_t i = 0; i < DES_BLOCK_SIZE; ++i) {
            output[i] = input[i] ^ key[i % key.size()] ^ 0xAA;
        }
    }
    
    size_t block_size() const override { return DES_BLOCK_SIZE; }
    size_t key_size() const override { return DES_KEY_SIZE; }
};

// Реализация TripleDES
class TripleDES : public BlockCipher {
private:
    std::vector<DES> des_ciphers;
    
public:
    TripleDES(const std::vector<uint8_t>& user_key) {
        std::vector<uint8_t> key1, key2, key3;
        
        if (user_key.size() >= 24) {
            key1.assign(user_key.begin(), user_key.begin() + 8);
            key2.assign(user_key.begin() + 8, user_key.begin() + 16);
            key3.assign(user_key.begin() + 16, user_key.begin() + 24);
        } else if (user_key.size() >= 16) {
            key1.assign(user_key.begin(), user_key.begin() + 8);
            key2.assign(user_key.begin() + 8, user_key.begin() + 16);
            key3 = key1; // K3 = K1 для совместимости с 2-ключевым 3DES
        } else {
            key1.assign(user_key.begin(), user_key.end());
            key1.resize(8, 0);
            key2 = key1;
            key3 = key1;
        }
        
        des_ciphers.emplace_back(key1);
        des_ciphers.emplace_back(key2);
        des_ciphers.emplace_back(key3);
    }
    
    void encrypt_block(const uint8_t* input, uint8_t* output) override {
        uint8_t temp[DES_BLOCK_SIZE];
        uint8_t temp2[DES_BLOCK_SIZE];
        
        // E(K1, D(K2, E(K3, plaintext)))
        des_ciphers[2].encrypt_block(input, temp);
        des_ciphers[1].decrypt_block(temp, temp2);
        des_ciphers[0].encrypt_block(temp2, output);
    }
    
    void decrypt_block(const uint8_t* input, uint8_t* output) override {
        uint8_t temp[DES_BLOCK_SIZE];
        uint8_t temp2[DES_BLOCK_SIZE];
        
        // D(K1, E(K2, D(K3, ciphertext)))
        des_ciphers[0].decrypt_block(input, temp);
        des_ciphers[1].encrypt_block(temp, temp2);
        des_ciphers[2].decrypt_block(temp2, output);
    }
    
    size_t block_size() const override { return DES_BLOCK_SIZE; }
    size_t key_size() const override { return TRIPLE_DES_KEY_SIZE; }
};

// Реализация DEAL (упрощенная)
class DEAL : public BlockCipher {
private:
    std::vector<uint8_t> key;
    
public:
    DEAL(const std::vector<uint8_t>& user_key) {
        key = user_key;
        if (key.size() < DEAL_KEY_SIZE) {
            key.resize(DEAL_KEY_SIZE, 0);
        } else {
            key.resize(DEAL_KEY_SIZE);
        }
    }
    
    void encrypt_block(const uint8_t* input, uint8_t* output) override {
        // Упрощенная имитация шифрования DEAL
        for (size_t i = 0; i < DEAL_BLOCK_SIZE; ++i) {
            output[i] = input[i] ^ key[i % key.size()] ^ 0xBB;
        }
    }
    
    void decrypt_block(const uint8_t* input, uint8_t* output) override {
        // Упрощенная имитация дешифрования DEAL
        for (size_t i = 0; i < DEAL_BLOCK_SIZE; ++i) {
            output[i] = input[i] ^ key[i % key.size()] ^ 0xBB;
        }
    }
    
    size_t block_size() const override { return DEAL_BLOCK_SIZE; }
    size_t key_size() const override { return DEAL_KEY_SIZE; }
};

// Класс для работы с набивкой
class Padding {
public:
    static std::vector<uint8_t> add_padding(const std::vector<uint8_t>& data, 
                                            size_t block_size, 
                                            PaddingMode mode) {
        std::vector<uint8_t> result = data;
        size_t padding_len = block_size - (data.size() % block_size);
        
        if (padding_len == 0) {
            padding_len = block_size; // Добавляем полный блок
        }
        
        result.resize(data.size() + padding_len);
        
        switch (mode) {
            case PaddingMode::ZEROS:
                // Заполняем нулями
                std::memset(result.data() + data.size(), 0, padding_len);
                break;
                
            case PaddingMode::ANSI_X923:
                // Заполняем нулями, последний байт - длина набивки
                std::memset(result.data() + data.size(), 0, padding_len - 1);
                result.back() = static_cast<uint8_t>(padding_len);
                break;
                
            case PaddingMode::PKCS7:
                // Заполняем значением длины набивки
                std::memset(result.data() + data.size(), 
                           static_cast<uint8_t>(padding_len), padding_len);
                break;
                
            case PaddingMode::ISO_10126:
                // Заполняем случайными байтами, последний - длина
                {
                    std::random_device rd;
                    std::mt19937 gen(rd());
                    std::uniform_int_distribution<int> dist(1, 255);
                    
                    for (size_t i = 0; i < padding_len - 1; ++i) {
                        result[data.size() + i] = static_cast<uint8_t>(dist(gen));
                    }
                    result.back() = static_cast<uint8_t>(padding_len);
                }
                break;
        }
        
        return result;
    }
    
    static std::vector<uint8_t> remove_padding(const std::vector<uint8_t>& data,
                                               size_t block_size,
                                               PaddingMode mode) {
        if (data.empty()) return data;
        
        size_t padding_len = 0;
        
        switch (mode) {
            case PaddingMode::ZEROS:
                // Ищем последний ненулевой байт
                {
                    size_t i = data.size() - 1;
                    while (i > 0 && data[i] == 0) {
                        --i;
                    }
                    padding_len = data.size() - i - 1;
                }
                break;
                
            case PaddingMode::ANSI_X923:
                padding_len = data.back();
                // Проверяем, что все предыдущие байты набивки - нули
                if (padding_len > 0 && padding_len <= block_size) {
                    for (size_t i = 0; i < padding_len - 1; ++i) {
                        if (data[data.size() - 1 - i] != 0) {
                            // Ошибка набивки, возвращаем как есть
                            return data;
                        }
                    }
                } else {
                    return data;
                }
                break;
                
            case PaddingMode::PKCS7:
                padding_len = data.back();
                // Проверяем, что все байты набивки равны padding_len
                if (padding_len > 0 && padding_len <= block_size) {
                    for (size_t i = 0; i < padding_len; ++i) {
                        if (data[data.size() - 1 - i] != padding_len) {
                            return data;
                        }
                    }
                } else {
                    return data;
                }
                break;
                
            case PaddingMode::ISO_10126:
                padding_len = data.back();
                break;
        }
        
        if (padding_len > 0 && padding_len <= block_size) {
            return std::vector<uint8_t>(data.begin(), data.end() - padding_len);
        }
        
        return data;
    }
};

// Класс для шифрования в различных режимах
class CipherModeProcessor {
private:
    std::unique_ptr<BlockCipher> cipher;
    CipherMode mode;
    PaddingMode padding_mode;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> last_ciphertext;
    std::vector<uint8_t> last_plaintext;
    std::mutex mode_mutex;
    
    // Генерация случайного дельта для режима Random Delta
    std::vector<uint8_t> generate_delta() {
        std::vector<uint8_t> delta(cipher->block_size());
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dist(0, 255);
        
        for (size_t i = 0; i < delta.size(); ++i) {
            delta[i] = static_cast<uint8_t>(dist(gen));
        }
        
        return delta;
    }
    
    void increment_counter(std::vector<uint8_t>& counter) {
        for (int i = counter.size() - 1; i >= 0; --i) {
            if (++counter[i] != 0) break;
        }
    }
    
public:
    CipherModeProcessor(std::unique_ptr<BlockCipher> c, CipherMode m, PaddingMode p, 
                       const std::vector<uint8_t>& initialization_vector)
        : cipher(std::move(c)), mode(m), padding_mode(p), iv(initialization_vector) {
        
        if (iv.size() < cipher->block_size()) {
            iv.resize(cipher->block_size(), 0);
        } else {
            iv.resize(cipher->block_size());
        }
        
        last_ciphertext = iv;
        last_plaintext = iv;
    }
    
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext) {
        std::lock_guard<std::mutex> lock(mode_mutex);
        
        // Добавляем набивку
        std::vector<uint8_t> padded = Padding::add_padding(plaintext, 
                                                           cipher->block_size(), 
                                                           padding_mode);
        
        std::vector<uint8_t> ciphertext;
        ciphertext.reserve(padded.size());
        
        size_t block_size = cipher->block_size();
        size_t num_blocks = padded.size() / block_size;
        
        std::vector<uint8_t> input_block(block_size);
        std::vector<uint8_t> output_block(block_size);
        
        switch (mode) {
            case CipherMode::ECB: {
                // Electronic Codebook
                for (size_t i = 0; i < num_blocks; ++i) {
                    cipher->encrypt_block(padded.data() + i * block_size, output_block.data());
                    ciphertext.insert(ciphertext.end(), output_block.begin(), output_block.end());
                }
                break;
            }
            
            case CipherMode::CBC: {
                // Cipher Block Chaining
                for (size_t i = 0; i < num_blocks; ++i) {
                    // XOR с предыдущим шифротекстом или IV
                    for (size_t j = 0; j < block_size; ++j) {
                        input_block[j] = padded[i * block_size + j] ^ last_ciphertext[j];
                    }
                    
                    cipher->encrypt_block(input_block.data(), output_block.data());
                    ciphertext.insert(ciphertext.end(), output_block.begin(), output_block.end());
                    
                    // Сохраняем для следующего блока
                    last_ciphertext = output_block;
                }
                break;
            }
            
            case CipherMode::PCBC: {
                // Propagating Cipher Block Chaining
                for (size_t i = 0; i < num_blocks; ++i) {
                    // XOR с предыдущим шифротекстом и предыдущим открытым текстом
                    for (size_t j = 0; j < block_size; ++j) {
                        input_block[j] = padded[i * block_size + j] ^ 
                                        last_ciphertext[j] ^ last_plaintext[j];
                    }
                    
                    cipher->encrypt_block(input_block.data(), output_block.data());
                    ciphertext.insert(ciphertext.end(), output_block.begin(), output_block.end());
                    
                    last_ciphertext = output_block;
                    last_plaintext.assign(padded.data() + i * block_size,
                                         padded.data() + (i + 1) * block_size);
                }
                break;
            }
            
            case CipherMode::CFB: {
                // Cipher Feedback
                for (size_t i = 0; i < num_blocks; ++i) {
                    cipher->encrypt_block(last_ciphertext.data(), output_block.data());
                    
                    for (size_t j = 0; j < block_size; ++j) {
                        output_block[j] ^= padded[i * block_size + j];
                    }
                    
                    ciphertext.insert(ciphertext.end(), output_block.begin(), output_block.end());
                    last_ciphertext = output_block;
                }
                break;
            }
            
            case CipherMode::OFB: {
                // Output Feedback
                std::vector<uint8_t> keystream = last_ciphertext;
                
                for (size_t i = 0; i < num_blocks; ++i) {
                    cipher->encrypt_block(keystream.data(), output_block.data());
                    keystream = output_block;
                    
                    for (size_t j = 0; j < block_size; ++j) {
                        output_block[j] ^= padded[i * block_size + j];
                    }
                    
                    ciphertext.insert(ciphertext.end(), output_block.begin(), output_block.end());
                }
                
                last_ciphertext = keystream;
                break;
            }
            
            case CipherMode::CTR: {
                // Counter
                std::vector<uint8_t> counter = iv;
                
                for (size_t i = 0; i < num_blocks; ++i) {
                    cipher->encrypt_block(counter.data(), output_block.data());
                    
                    for (size_t j = 0; j < block_size; ++j) {
                        output_block[j] ^= padded[i * block_size + j];
                    }
                    
                    ciphertext.insert(ciphertext.end(), output_block.begin(), output_block.end());
                    increment_counter(counter);
                }
                break;
            }
            
            case CipherMode::RANDOM_DELTA: {
                // Random Delta (упрощенная реализация)
                std::vector<uint8_t> delta = generate_delta();
                std::vector<uint8_t> current = last_ciphertext;
                
                for (size_t i = 0; i < num_blocks; ++i) {
                    cipher->encrypt_block(current.data(), output_block.data());
                    
                    for (size_t j = 0; j < block_size; ++j) {
                        output_block[j] ^= padded[i * block_size + j];
                    }
                    
                    ciphertext.insert(ciphertext.end(), output_block.begin(), output_block.end());
                    
                    // Обновляем current с дельтой
                    for (size_t j = 0; j < block_size; ++j) {
                        current[j] += delta[j];
                    }
                }
                
                last_ciphertext = current;
                break;
            }
        }
        
        return ciphertext;
    }
    
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext) {
        std::lock_guard<std::mutex> lock(mode_mutex);
        
        std::vector<uint8_t> plaintext;
        plaintext.reserve(ciphertext.size());
        
        size_t block_size = cipher->block_size();
        
        if (ciphertext.size() % block_size != 0) {
            throw std::runtime_error("Ciphertext size must be multiple of block size");
        }
        
        size_t num_blocks = ciphertext.size() / block_size;
        
        std::vector<uint8_t> input_block(block_size);
        std::vector<uint8_t> output_block(block_size);
        
        switch (mode) {
            case CipherMode::ECB: {
                for (size_t i = 0; i < num_blocks; ++i) {
                    cipher->decrypt_block(ciphertext.data() + i * block_size, output_block.data());
                    plaintext.insert(plaintext.end(), output_block.begin(), output_block.end());
                }
                break;
            }
            
            case CipherMode::CBC: {
                for (size_t i = 0; i < num_blocks; ++i) {
                    cipher->decrypt_block(ciphertext.data() + i * block_size, output_block.data());
                    
                    for (size_t j = 0; j < block_size; ++j) {
                        output_block[j] ^= last_ciphertext[j];
                    }
                    
                    plaintext.insert(plaintext.end(), output_block.begin(), output_block.end());
                    last_ciphertext.assign(ciphertext.data() + i * block_size,
                                          ciphertext.data() + (i + 1) * block_size);
                }
                break;
            }
            
            case CipherMode::PCBC: {
                for (size_t i = 0; i < num_blocks; ++i) {
                    cipher->decrypt_block(ciphertext.data() + i * block_size, output_block.data());
                    
                    for (size_t j = 0; j < block_size; ++j) {
                        output_block[j] ^= last_ciphertext[j] ^ last_plaintext[j];
                    }
                    
                    plaintext.insert(plaintext.end(), output_block.begin(), output_block.end());
                    
                    last_ciphertext.assign(ciphertext.data() + i * block_size,
                                          ciphertext.data() + (i + 1) * block_size);
                    last_plaintext = output_block;
                }
                break;
            }
            
            case CipherMode::CFB: {
                for (size_t i = 0; i < num_blocks; ++i) {
                    cipher->encrypt_block(last_ciphertext.data(), output_block.data());
                    
                    for (size_t j = 0; j < block_size; ++j) {
                        output_block[j] ^= ciphertext[i * block_size + j];
                    }
                    
                    plaintext.insert(plaintext.end(), output_block.begin(), output_block.end());
                    last_ciphertext.assign(ciphertext.data() + i * block_size,
                                          ciphertext.data() + (i + 1) * block_size);
                }
                break;
            }
            
            case CipherMode::OFB: {
                std::vector<uint8_t> keystream = last_ciphertext;
                
                for (size_t i = 0; i < num_blocks; ++i) {
                    cipher->encrypt_block(keystream.data(), output_block.data());
                    keystream = output_block;
                    
                    for (size_t j = 0; j < block_size; ++j) {
                        output_block[j] ^= ciphertext[i * block_size + j];
                    }
                    
                    plaintext.insert(plaintext.end(), output_block.begin(), output_block.end());
                }
                
                last_ciphertext = keystream;
                break;
            }
            
            case CipherMode::CTR: {
                std::vector<uint8_t> counter = iv;
                
                for (size_t i = 0; i < num_blocks; ++i) {
                    cipher->encrypt_block(counter.data(), output_block.data());
                    
                    for (size_t j = 0; j < block_size; ++j) {
                        output_block[j] ^= ciphertext[i * block_size + j];
                    }
                    
                    plaintext.insert(plaintext.end(), output_block.begin(), output_block.end());
                    increment_counter(counter);
                }
                break;
            }
            
            case CipherMode::RANDOM_DELTA: {
                std::vector<uint8_t> delta = generate_delta();
                std::vector<uint8_t> current = last_ciphertext;
                
                for (size_t i = 0; i < num_blocks; ++i) {
                    cipher->encrypt_block(current.data(), output_block.data());
                    
                    for (size_t j = 0; j < block_size; ++j) {
                        output_block[j] ^= ciphertext[i * block_size + j];
                    }
                    
                    plaintext.insert(plaintext.end(), output_block.begin(), output_block.end());
                    
                    for (size_t j = 0; j < block_size; ++j) {
                        current[j] += delta[j];
                    }
                }
                
                last_ciphertext = current;
                break;
            }
        }
        
        // Удаляем набивку
        return Padding::remove_padding(plaintext, block_size, padding_mode);
    }
};

// Класс для многопоточной обработки файлов
class FileProcessor {
private:
    std::unique_ptr<CipherModeProcessor> processor;
    size_t num_threads;
    
public:
    FileProcessor(std::unique_ptr<CipherModeProcessor> p, size_t threads = 4)
        : processor(std::move(p)), num_threads(threads) {}
    
    void process_file(const std::string& input_file, const std::string& output_file, bool encrypt_mode) {
        // Читаем входной файл
        std::ifstream in(input_file, std::ios::binary);
        if (!in) {
            throw std::runtime_error("Cannot open input file: " + input_file);
        }
        
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(in)),
                                   std::istreambuf_iterator<char>());
        in.close();
        
        std::vector<uint8_t> result;
        
        if (encrypt_mode) {
            result = processor->encrypt(data);
        } else {
            result = processor->decrypt(data);
        }
        
        // Записываем результат
        std::ofstream out(output_file, std::ios::binary);
        if (!out) {
            throw std::runtime_error("Cannot create output file: " + output_file);
        }
        
        out.write(reinterpret_cast<const char*>(result.data()), result.size());
        out.close();
    }
    
    void process_file_parallel(const std::string& input_file, const std::string& output_file, bool encrypt_mode) {
        // Для простоты используем последовательную обработку в одном потоке
        // В реальном проекте здесь была бы реализация многопоточной обработки
        process_file(input_file, output_file, encrypt_mode);
    }
};

// Функции для ввода с консоли
int get_menu_choice(const std::string& prompt, const std::vector<std::string>& options) {
    std::cout << prompt << std::endl;
    for (size_t i = 0; i < options.size(); ++i) {
        std::cout << i + 1 << ". " << options[i] << std::endl;
    }
    
    int choice;
    std::cin >> choice;
    
    if (choice < 1 || choice > static_cast<int>(options.size())) {
        std::cout << "Invalid choice. Using default (1)." << std::endl;
        return 1;
    }
    
    return choice;
}

std::string get_input_filename() {
    std::string filename;
    std::cout << "Enter filename (should be in 'input' folder): ";
    std::cin >> filename;
    return filename;
}

std::vector<uint8_t> get_key_from_user(size_t key_size, PaddingMode padding_mode) {
    std::string key_str;
    std::cout << "Enter key (any string): ";
    std::cin.ignore();
    std::getline(std::cin, key_str);
    
    std::vector<uint8_t> key(key_str.begin(), key_str.end());
    
    // Заполняем ключ до нужного размера
    if (key.size() < key_size) {
        size_t old_size = key.size();
        key.resize(key_size);
        
        switch (padding_mode) {
            case PaddingMode::ZEROS:
                std::memset(key.data() + old_size, 0, key_size - old_size);
                break;
            case PaddingMode::ANSI_X923:
                std::memset(key.data() + old_size, 0, key_size - old_size - 1);
                key.back() = static_cast<uint8_t>(key_size - old_size);
                break;
            case PaddingMode::PKCS7:
                std::memset(key.data() + old_size, 
                           static_cast<uint8_t>(key_size - old_size), 
                           key_size - old_size);
                break;
            case PaddingMode::ISO_10126:
                {
                    std::random_device rd;
                    std::mt19937 gen(rd());
                    std::uniform_int_distribution<int> dist(1, 255);
                    
                    for (size_t i = old_size; i < key_size - 1; ++i) {
                        key[i] = static_cast<uint8_t>(dist(gen));
                    }
                    key.back() = static_cast<uint8_t>(key_size - old_size);
                }
                break;
        }
    } else {
        key.resize(key_size);
    }
    
    return key;
}

int main() {
    try {
        std::cout << "=== File Encryption/Decryption Program ===" << std::endl;
        
        // Выбор режима работы
        std::vector<std::string> mode_options = {"Encrypt", "Decrypt"};
        int mode_choice = get_menu_choice("Select mode:", mode_options);
        bool encrypt_mode = (mode_choice == 1);
        
        // Выбор алгоритма
        std::vector<std::string> algo_options = {"DES", "TripleDES", "DEAL"};
        int algo_choice = get_menu_choice("Select algorithm:", algo_options);
        
        // Выбор режима шифрования
        std::vector<std::string> cipher_options = {
            "ECB", "CBC", "PCBC", "CFB", "OFB", "CTR", "Random Delta"
        };
        int cipher_choice = get_menu_choice("Select cipher mode:", cipher_options);
        
        // Выбор режима набивки
        std::vector<std::string> padding_options = {
            "Zeros", "ANSI X9.23", "PKCS7", "ISO 10126"
        };
        int padding_choice = get_menu_choice("Select padding mode:", padding_options);
        
        // Получаем имя файла
        std::string filename = get_input_filename();
        
        // Формируем пути
        std::string input_path = "input/" + filename;
        std::string output_filename;
        
        size_t dot_pos = filename.find_last_of('.');
        if (dot_pos != std::string::npos) {
            output_filename = filename.substr(0, dot_pos) + "_shifr" + filename.substr(dot_pos);
        } else {
            output_filename = filename + "_shifr";
        }
        
        std::string output_path = "output/" + output_filename;
        
        // Создаем папки, если их нет
        fs::create_directories("input");
        fs::create_directories("output");
        
        // Проверяем существование входного файла
        if (!fs::exists(input_path)) {
            std::cerr << "Error: Input file does not exist: " << input_path << std::endl;
            return 1;
        }
        
        // Определяем размер ключа для выбранного алгоритма
        size_t key_size;
        switch (static_cast<Algorithm>(algo_choice - 1)) {
            case Algorithm::DES: key_size = DES_KEY_SIZE; break;
            case Algorithm::TRIPLE_DES: key_size = TRIPLE_DES_KEY_SIZE; break;
            case Algorithm::DEAL: key_size = DEAL_KEY_SIZE; break;
            default: key_size = 8;
        }
        
        // Получаем ключ
        PaddingMode padding_mode = static_cast<PaddingMode>(padding_choice - 1);
        std::vector<uint8_t> key = get_key_from_user(key_size, padding_mode);
        
        // Генерируем IV
        std::vector<uint8_t> iv(8, 0); // Для DES/TripleDES
        if (algo_choice == 3) { // DEAL
            iv.resize(16, 0);
        }
        
        // Создаем шифр
        std::unique_ptr<BlockCipher> cipher;
        switch (static_cast<Algorithm>(algo_choice - 1)) {
            case Algorithm::DES:
                cipher = std::make_unique<DES>(key);
                break;
            case Algorithm::TRIPLE_DES:
                cipher = std::make_unique<TripleDES>(key);
                break;
            case Algorithm::DEAL:
                cipher = std::make_unique<DEAL>(key);
                break;
        }
        
        // Создаем процессор режима
        auto processor = std::make_unique<CipherModeProcessor>(
            std::move(cipher),
            static_cast<CipherMode>(cipher_choice - 1),
            padding_mode,
            iv
        );
        
        // Создаем обработчик файлов
        FileProcessor file_processor(std::move(processor));
        
        // Выполняем операцию
        std::cout << (encrypt_mode ? "Encrypting" : "Decrypting") << " file: " << filename << std::endl;
        std::cout << "Output file: " << output_path << std::endl;
        
        if (encrypt_mode) {
            file_processor.process_file_parallel(input_path, output_path, true);
            std::cout << "Encryption completed successfully!" << std::endl;
        } else {
            file_processor.process_file_parallel(input_path, output_path, false);
            std::cout << "Decryption completed successfully!" << std::endl;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}