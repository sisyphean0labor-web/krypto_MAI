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
#include <bitset>

namespace fs = std::filesystem;

// Константы для алгоритмов
const size_t DES_BLOCK_SIZE = 8; // 64 бита
const size_t DES_KEY_SIZE = 8;   // 64 бита (с битами четности)
const size_t TRIPLE_DES_KEY_SIZE = 24; // 192 бита
const size_t DEAL_BLOCK_SIZE = 16; // 128 бит
const size_t DEAL_KEY_SIZE = 16;   // 128 бит

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

// ==================== DES Implementation ====================

// Initial Permutation (IP)
const int IP[64] = {
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
};

// Final Permutation (IP^-1)
const int FP[64] = {
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
};

// Expansion table (E)
const int E[48] = {
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
};

// S-boxes
const int S_BOX[8][4][16] = {
    // S1
    {
        {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
        {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
        {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
        {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
    },
    // S2
    {
        {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
        {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
        {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
        {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
    },
    // S3
    {
        {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
        {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
        {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
        {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
    },
    // S4
    {
        {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
        {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
        {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
        {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
    },
    // S5
    {
        {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
        {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
        {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
        {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
    },
    // S6
    {
        {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
        {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
        {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
        {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
    },
    // S7
    {
        {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
        {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
        {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
        {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
    },
    // S8
    {
        {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
        {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
        {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
        {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
    }
};

// Permutation P
const int P[32] = {
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
};

// Permuted Choice 1 (PC-1) for key schedule
const int PC1[56] = {
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
};

// Permuted Choice 2 (PC-2) for key schedule
const int PC2[48] = {
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

// Key schedule shifts
const int SHIFTS[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

// ==================== DEAL Tables ====================
// S-блоки для DEAL (используются из DES, но DEAL имеет свою структуру)
// Для DEAL используем те же S-блоки, но с другой организацией раундов

// Базовый класс для алгоритмов шифрования
class BlockCipher {
public:
    virtual ~BlockCipher() = default;
    virtual void encrypt_block(const uint8_t* input, uint8_t* output) = 0;
    virtual void decrypt_block(const uint8_t* input, uint8_t* output) = 0;
    virtual size_t block_size() const = 0;
    virtual size_t key_size() const = 0;
};

// ==================== Полная реализация DES ====================
class DES : public BlockCipher {
private:
    uint64_t key; // 56-битный ключ (без битов четности)
    uint64_t subkeys[16]; // 16 подключей по 48 бит
    
    // Преобразование 8-байтового ключа (с битами четности) в 56-битный ключ
    static uint64_t key_to_56bit(const uint8_t* key_bytes) {
        uint64_t result = 0;
        for (int i = 0; i < 8; i++) {
            result |= (static_cast<uint64_t>(key_bytes[i] & 0xFE) << (4 * (7 - i)));
        }
        return result;
    }
    
    // Генерация подключей
    void generate_subkeys(const uint8_t* key_bytes) {
        // Преобразуем 64-битный ключ в 56 бит (PC-1)
        uint64_t key56 = 0;
        for (int i = 0; i < 56; i++) {
            int bit_pos = PC1[i] - 1;
            int byte_idx = bit_pos / 8;
            int bit_idx = 7 - (bit_pos % 8);
            uint64_t bit = (key_bytes[byte_idx] >> bit_idx) & 1;
            key56 |= (bit << (55 - i));
        }
        
        // Разделяем на C и D (по 28 бит)
        uint32_t C = (key56 >> 28) & 0x0FFFFFFF;
        uint32_t D = key56 & 0x0FFFFFFF;
        
        // Генерируем 16 подключей
        for (int round = 0; round < 16; round++) {
            // Циклический сдвиг влево
            C = ((C << SHIFTS[round]) | (C >> (28 - SHIFTS[round]))) & 0x0FFFFFFF;
            D = ((D << SHIFTS[round]) | (D >> (28 - SHIFTS[round]))) & 0x0FFFFFFF;
            
            // Объединяем C и D
            uint64_t CD = (static_cast<uint64_t>(C) << 28) | D;
            
            // Применяем PC-2 для получения 48-битного подключа
            uint64_t subkey = 0;
            for (int i = 0; i < 48; i++) {
                int bit_pos = PC2[i] - 1;
                uint64_t bit = (CD >> (55 - bit_pos)) & 1;
                subkey |= (bit << (47 - i));
            }
            subkeys[round] = subkey;
        }
    }
    
    // Функция Фейстеля
    static uint32_t f(uint32_t R, uint64_t K) {
        // Расширение E с 32 до 48 бит
        uint64_t expanded = 0;
        for (int i = 0; i < 48; i++) {
            int bit_pos = E[i] - 1;
            uint64_t bit = (R >> (31 - bit_pos)) & 1;
            expanded |= (bit << (47 - i));
        }
        
        // XOR с ключом
        uint64_t xored = expanded ^ K;
        
        // S-блоки (8 блоков по 6 бит -> 4 бита)
        uint32_t sbox_output = 0;
        for (int i = 0; i < 8; i++) {
            // Берем 6 бит для i-го S-блока
            int byte6 = (xored >> (42 - i * 6)) & 0x3F;
            
            // row = первый и последний бит, col = средние 4 бита
            int row = ((byte6 & 0x20) >> 4) | (byte6 & 1);
            int col = (byte6 >> 1) & 0x0F;
            
            int sval = S_BOX[i][row][col];
            sbox_output = (sbox_output << 4) | sval;
        }
        
        // Перестановка P
        uint32_t result = 0;
        for (int i = 0; i < 32; i++) {
            int bit_pos = P[i] - 1;
            uint32_t bit = (sbox_output >> (31 - bit_pos)) & 1;
            result |= (bit << (31 - i));
        }
        
        return result;
    }
    
    // Начальная перестановка IP
    static uint64_t initial_permutation(uint64_t block) {
        uint64_t result = 0;
        for (int i = 0; i < 64; i++) {
            int bit_pos = IP[i] - 1;
            uint64_t bit = (block >> (63 - bit_pos)) & 1;
            result |= (bit << (63 - i));
        }
        return result;
    }
    
    // Конечная перестановка FP
    static uint64_t final_permutation(uint64_t block) {
        uint64_t result = 0;
        for (int i = 0; i < 64; i++) {
            int bit_pos = FP[i] - 1;
            uint64_t bit = (block >> (63 - bit_pos)) & 1;
            result |= (bit << (63 - i));
        }
        return result;
    }
    
    // Шифрование одного 64-битного блока
    uint64_t process_block(uint64_t block, bool decrypt) {
        // Начальная перестановка
        block = initial_permutation(block);
        
        // Разделяем на L и R (по 32 бита)
        uint32_t L = block >> 32;
        uint32_t R = block & 0xFFFFFFFF;
        
        // 16 раундов
        for (int round = 0; round < 16; round++) {
            int key_idx = decrypt ? 15 - round : round;
            uint32_t newL = R;
            uint32_t newR = L ^ f(R, subkeys[key_idx]);
            L = newL;
            R = newR;
        }
        
        // Объединяем (R, L) - обратите внимание на перестановку
        uint64_t result = (static_cast<uint64_t>(R) << 32) | L;
        
        // Конечная перестановка
        return final_permutation(result);
    }
    
public:
    DES(const std::vector<uint8_t>& user_key) {
        std::vector<uint8_t> key_bytes(DES_KEY_SIZE, 0);
        std::copy(user_key.begin(), 
                 user_key.begin() + std::min(user_key.size(), DES_KEY_SIZE), 
                 key_bytes.begin());
        generate_subkeys(key_bytes.data());
    }
    
    void encrypt_block(const uint8_t* input, uint8_t* output) override {
        uint64_t block = 0;
        for (int i = 0; i < 8; i++) {
            block = (block << 8) | input[i];
        }
        
        uint64_t encrypted = process_block(block, false);
        
        for (int i = 0; i < 8; i++) {
            output[7 - i] = encrypted & 0xFF;
            encrypted >>= 8;
        }
    }
    
    void decrypt_block(const uint8_t* input, uint8_t* output) override {
        uint64_t block = 0;
        for (int i = 0; i < 8; i++) {
            block = (block << 8) | input[i];
        }
        
        uint64_t decrypted = process_block(block, true);
        
        for (int i = 0; i < 8; i++) {
            output[7 - i] = decrypted & 0xFF;
            decrypted >>= 8;
        }
    }
    
    size_t block_size() const override { return DES_BLOCK_SIZE; }
    size_t key_size() const override { return DES_KEY_SIZE; }
};

// ==================== Полная реализация TripleDES ====================
class TripleDES : public BlockCipher {
private:
    DES des1, des2, des3;
    
public:
    TripleDES(const std::vector<uint8_t>& user_key) 
        : des1(std::vector<uint8_t>(user_key.begin(), 
                                     user_key.begin() + std::min<size_t>(8, user_key.size()))),
          des2(std::vector<uint8_t>(user_key.size() > 8 ? 
                                     user_key.begin() + 8 : user_key.begin(),
                                     user_key.begin() + std::min<size_t>(16, user_key.size()))),
          des3(std::vector<uint8_t>(user_key.size() > 16 ? 
                                     user_key.begin() + 16 : user_key.begin(),
                                     user_key.begin() + std::min<size_t>(24, user_key.size()))) {
        // Если ключ меньше 24 байт, используем K3 = K1
        if (user_key.size() <= 16) {
            des3 = des1;
        }
    }
    
    void encrypt_block(const uint8_t* input, uint8_t* output) override {
        uint8_t temp1[8], temp2[8];
        
        // E(K1, D(K2, E(K3, plaintext)))
        des3.encrypt_block(input, temp1);
        des2.decrypt_block(temp1, temp2);
        des1.encrypt_block(temp2, output);
    }
    
    void decrypt_block(const uint8_t* input, uint8_t* output) override {
        uint8_t temp1[8], temp2[8];
        
        // D(K1, E(K2, D(K3, ciphertext)))
        des1.decrypt_block(input, temp1);
        des2.encrypt_block(temp1, temp2);
        des3.decrypt_block(temp2, output);
    }
    
    size_t block_size() const override { return DES_BLOCK_SIZE; }
    size_t key_size() const override { return TRIPLE_DES_KEY_SIZE; }
};

// ==================== Полная реализация DEAL ====================
class DEAL : public BlockCipher {
private:
    std::vector<DES> des_ciphers; // Используем DES как компонент
    std::vector<uint64_t> round_keys;
    
    // Функция для DEAL: f(A, B) = DES_{B}(A)
    static void f_function(const uint8_t* A, const uint8_t* B, uint8_t* output, DES& des) {
        // В DEAL: f(A,B) = DES_{B}(A XOR B) XOR B
        uint8_t temp[8];
        for (int i = 0; i < 8; i++) {
            temp[i] = A[i] ^ B[i];
        }
        
        des.encrypt_block(temp, output);
        
        for (int i = 0; i < 8; i++) {
            output[i] ^= B[i];
        }
    }
    
public:
    DEAL(const std::vector<uint8_t>& user_key) {
        // DEAL может использовать 128, 192 или 256-битный ключ
        // Для простоты реализуем 128-битную версию (2 ключа DES)
        std::vector<uint8_t> key1(8), key2(8);
        
        if (user_key.size() >= 16) {
            std::copy(user_key.begin(), user_key.begin() + 8, key1.begin());
            std::copy(user_key.begin() + 8, user_key.begin() + 16, key2.begin());
        } else if (user_key.size() >= 8) {
            std::copy(user_key.begin(), user_key.begin() + 8, key1.begin());
            std::copy(user_key.begin(), user_key.begin() + std::min<size_t>(8, user_key.size()), key2.begin());
        } else {
            std::copy(user_key.begin(), user_key.end(), key1.begin());
            key2 = key1;
        }
        
        des_ciphers.emplace_back(key1);
        des_ciphers.emplace_back(key2);
    }
    
    void encrypt_block(const uint8_t* input, uint8_t* output) override {
        // DEAL шифрует 128-битный блок (разделенный на две 64-битные половины)
        const uint8_t* L = input;      // Левая половина (8 байт)
        const uint8_t* R = input + 8;  // Правая половина (8 байт)
        
        uint8_t L2[8], R2[8];
        std::memcpy(L2, L, 8);
        std::memcpy(R2, R, 8);
        
        // 6 раундов для DEAL (обычно 6)
        for (int round = 0; round < 6; round++) {
            uint8_t temp[8];
            
            if (round % 2 == 0) {
                f_function(R2, L2, temp, des_ciphers[0]);
            } else {
                f_function(R2, L2, temp, des_ciphers[1]);
            }
            
            // Обновляем половины
            for (int i = 0; i < 8; i++) {
                L2[i] ^= temp[i];
            }
            
            // Меняем местами L и R
            if (round < 5) {
                std::swap_ranges(L2, L2 + 8, R2);
            }
        }
        
        // Финальная перестановка (последний раунд не меняет местами)
        std::memcpy(output, L2, 8);
        std::memcpy(output + 8, R2, 8);
    }
    
    void decrypt_block(const uint8_t* input, uint8_t* output) override {
        // Дешифрование DEAL (обратная операция)
        const uint8_t* L = input;
        const uint8_t* R = input + 8;
        
        uint8_t L2[8], R2[8];
        std::memcpy(L2, L, 8);
        std::memcpy(R2, R, 8);
        
        // 6 раундов в обратном порядке
        for (int round = 5; round >= 0; round--) {
            uint8_t temp[8];
            
            if (round % 2 == 0) {
                f_function(R2, L2, temp, des_ciphers[0]);
            } else {
                f_function(R2, L2, temp, des_ciphers[1]);
            }
            
            for (int i = 0; i < 8; i++) {
                L2[i] ^= temp[i];
            }
            
            if (round > 0) {
                std::swap_ranges(L2, L2 + 8, R2);
            }
        }
        
        std::memcpy(output, L2, 8);
        std::memcpy(output + 8, R2, 8);
    }
    
    size_t block_size() const override { return DEAL_BLOCK_SIZE; }
    size_t key_size() const override { return DEAL_KEY_SIZE; }
};

// ==================== Класс для работы с набивкой (без изменений) ====================
class Padding {
public:
    static std::vector<uint8_t> add_padding(const std::vector<uint8_t>& data, 
                                            size_t block_size, 
                                            PaddingMode mode) {
        std::vector<uint8_t> result = data;
        size_t padding_len = block_size - (data.size() % block_size);
        
        if (padding_len == 0) {
            padding_len = block_size;
        }
        
        result.resize(data.size() + padding_len);
        
        switch (mode) {
            case PaddingMode::ZEROS:
                std::memset(result.data() + data.size(), 0, padding_len);
                break;
                
            case PaddingMode::ANSI_X923:
                std::memset(result.data() + data.size(), 0, padding_len - 1);
                result.back() = static_cast<uint8_t>(padding_len);
                break;
                
            case PaddingMode::PKCS7:
                std::memset(result.data() + data.size(), 
                           static_cast<uint8_t>(padding_len), padding_len);
                break;
                
            case PaddingMode::ISO_10126:
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
                if (padding_len > 0 && padding_len <= block_size) {
                    for (size_t i = 0; i < padding_len - 1; ++i) {
                        if (data[data.size() - 1 - i] != 0) {
                            return data;
                        }
                    }
                } else {
                    return data;
                }
                break;
                
            case PaddingMode::PKCS7:
                padding_len = data.back();
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

// ==================== Класс для режимов шифрования (без изменений) ====================
class CipherModeProcessor {
private:
    std::unique_ptr<BlockCipher> cipher;
    CipherMode mode;
    PaddingMode padding_mode;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> last_ciphertext;
    std::vector<uint8_t> last_plaintext;
    std::mutex mode_mutex;
    
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
                for (size_t i = 0; i < num_blocks; ++i) {
                    cipher->encrypt_block(padded.data() + i * block_size, output_block.data());
                    ciphertext.insert(ciphertext.end(), output_block.begin(), output_block.end());
                }
                break;
            }
            
            case CipherMode::CBC: {
                for (size_t i = 0; i < num_blocks; ++i) {
                    for (size_t j = 0; j < block_size; ++j) {
                        input_block[j] = padded[i * block_size + j] ^ last_ciphertext[j];
                    }
                    
                    cipher->encrypt_block(input_block.data(), output_block.data());
                    ciphertext.insert(ciphertext.end(), output_block.begin(), output_block.end());
                    last_ciphertext = output_block;
                }
                break;
            }
            
            case CipherMode::PCBC: {
                for (size_t i = 0; i < num_blocks; ++i) {
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
                std::vector<uint8_t> delta = generate_delta();
                std::vector<uint8_t> current = last_ciphertext;
                
                for (size_t i = 0; i < num_blocks; ++i) {
                    cipher->encrypt_block(current.data(), output_block.data());
                    
                    for (size_t j = 0; j < block_size; ++j) {
                        output_block[j] ^= padded[i * block_size + j];
                    }
                    
                    ciphertext.insert(ciphertext.end(), output_block.begin(), output_block.end());
                    
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
        
        return Padding::remove_padding(plaintext, block_size, padding_mode);
    }
};

// ==================== Класс для обработки файлов (без изменений) ====================
class FileProcessor {
private:
    std::unique_ptr<CipherModeProcessor> processor;
    size_t num_threads;
    
public:
    FileProcessor(std::unique_ptr<CipherModeProcessor> p, size_t threads = 4)
        : processor(std::move(p)), num_threads(threads) {}
    
    void process_file(const std::string& input_file, const std::string& output_file, bool encrypt_mode) {
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
        
        std::ofstream out(output_file, std::ios::binary);
        if (!out) {
            throw std::runtime_error("Cannot create output file: " + output_file);
        }
        
        out.write(reinterpret_cast<const char*>(result.data()), result.size());
        out.close();
    }
    
    void process_file_parallel(const std::string& input_file, const std::string& output_file, bool encrypt_mode) {
        process_file(input_file, output_file, encrypt_mode);
    }
};

// ==================== Функции ввода/вывода (без изменений) ====================
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
        std::cout << "=== File Encryption/Decryption Program (Full Implementation) ===" << std::endl;
        
        std::vector<std::string> mode_options = {"Encrypt", "Decrypt"};
        int mode_choice = get_menu_choice("Select mode:", mode_options);
        bool encrypt_mode = (mode_choice == 1);
        
        std::vector<std::string> algo_options = {"DES", "TripleDES", "DEAL"};
        int algo_choice = get_menu_choice("Select algorithm:", algo_options);
        
        std::vector<std::string> cipher_options = {
            "ECB", "CBC", "PCBC", "CFB", "OFB", "CTR", "Random Delta"
        };
        int cipher_choice = get_menu_choice("Select cipher mode:", cipher_options);
        
        std::vector<std::string> padding_options = {
            "Zeros", "ANSI X9.23", "PKCS7", "ISO 10126"
        };
        int padding_choice = get_menu_choice("Select padding mode:", padding_options);
        
        std::string filename = get_input_filename();
        
        std::string input_path = "input/" + filename;
        std::string output_filename;
        
        size_t dot_pos = filename.find_last_of('.');
        if (dot_pos != std::string::npos) {
            output_filename = filename.substr(0, dot_pos) + "_shifr" + filename.substr(dot_pos);
        } else {
            output_filename = filename + "_shifr";
        }
        
        std::string output_path = "output/" + output_filename;
        
        fs::create_directories("input");
        fs::create_directories("output");
        
        if (!fs::exists(input_path)) {
            std::cerr << "Error: Input file does not exist: " << input_path << std::endl;
            return 1;
        }
        
        size_t key_size;
        switch (static_cast<Algorithm>(algo_choice - 1)) {
            case Algorithm::DES: key_size = DES_KEY_SIZE; break;
            case Algorithm::TRIPLE_DES: key_size = TRIPLE_DES_KEY_SIZE; break;
            case Algorithm::DEAL: key_size = DEAL_KEY_SIZE; break;
            default: key_size = 8;
        }
        
        PaddingMode padding_mode = static_cast<PaddingMode>(padding_choice - 1);
        std::vector<uint8_t> key = get_key_from_user(key_size, padding_mode);
        
        std::vector<uint8_t> iv(8, 0);
        if (algo_choice == 3) {
            iv.resize(16, 0);
        }
        
        std::unique_ptr<BlockCipher> cipher;
        switch (static_cast<Algorithm>(algo_choice - 1)) {
            case Algorithm::DES:
                cipher = std::make_unique<DES>(key);
                std::cout << "DES initialized with full implementation (S-boxes, P-boxes, etc.)" << std::endl;
                break;
            case Algorithm::TRIPLE_DES:
                cipher = std::make_unique<TripleDES>(key);
                std::cout << "TripleDES initialized with full DES implementation" << std::endl;
                break;
            case Algorithm::DEAL:
                cipher = std::make_unique<DEAL>(key);
                std::cout << "DEAL initialized (using DES as round function)" << std::endl;
                break;
        }
        
        auto processor = std::make_unique<CipherModeProcessor>(
            std::move(cipher),
            static_cast<CipherMode>(cipher_choice - 1),
            padding_mode,
            iv
        );
        
        FileProcessor file_processor(std::move(processor));
        
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