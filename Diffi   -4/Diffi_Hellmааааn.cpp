#include <iostream>
#include <cmath>
#include <random>
#include <string>
#include <iomanip>
#include <vector>
#include <sstream>


/*Протокол Диффи-Хеллмана позволяет двум сторонам (Алиса и Боб) создать общий секретный ключ по открытому каналу
 Стороны выбирают общие параметры p(простое число) и g(первообразный корень), 
 затем генерируют закрытые ключи a, b и обмениваются открытыми A = g^a*(mod p), B = g^b*(mod p),
вычисляя общий секретный ключ K = A^b*(mod p) = B^b*(mod p) = g^(ab)*(mod p)
*/



// Функция для быстрого возведения в степень по модулю
long long modPow(long long base, long long exponent, long long modulus) {
    if (modulus == 1) return 0;
    
    long long result = 1;
    base = base % modulus; //Основание к диапазону [0, modulus-1]
    

    while (exponent > 0) {
            //Если текущий бит показателя степени равен 1
        if (exponent & 1) {
            result = (result * base) % modulus;//умножаем результат на текущее значение base по модулю
        }
        base = (base * base) % modulus;// base в квадрат по модулю
        exponent >>= 1;//Сдвигаем показатель степени вправо на 1 бит
    }
    
    return result;
}
/*Вычисляем 5^13 mod 23
long long result = modPow(5, 13, 23);*/



// Проверка числа на простоту(упрощенная)
bool isPrime(long long n) {
    if (n <= 1) return false;
    if (n <= 3) return true;
    if (n % 2 == 0 || n % 3 == 0) return false;
    
    for (long long i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0) return false;
    }
    return true;
}

// Генерация случайного числа в заданном диапазоне
long long generateRandom(long long min, long long max) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<long long> dis(min, max);
    return dis(gen);
}

// XOR шифрование для демонстрации
std::string xorEncryptDecrypt(const std::string& input, long long key) {
    std::string output = input;
    // Используются младшие байты ключа для XOR
    unsigned char keyBytes[8];
    for (int i = 0; i < 8; i++) {
        keyBytes[i] = (key >> (i * 8)) & 0xFF;
    }
    
    for (size_t i = 0; i < input.length(); i++) {
        output[i] = input[i] ^ keyBytes[i % 8];
    }
    
    return output;
}

// Класс участника обмена ключами
class DiffieHellmanParticipant {
private:
    long long privateKey;
    long long publicKey;
    long long sharedSecret;
    long long p; // общее простое число
    long long g; // генератор
    
public:
    DiffieHellmanParticipant(long long p_, long long g_) : p(p_), g(g_), sharedSecret(0) {
        // Генерируем закрытый ключ (2 <= privateKey <= p-2)
        privateKey = generateRandom(2, p - 2);
        // Вычисляем открытый ключ: g^privateKey mod p
        publicKey = modPow(g, privateKey, p);
        
        std::cout << "Сгенерирован закрытый ключ: " << privateKey << std::endl;
        std::cout << "Вычислен открытый ключ: " << publicKey << std::endl;
    }
    
    // Получить открытый ключ
    long long getPublicKey() const {
        return publicKey;
    }
    
    // Вычислить общий секрет на основе открытого ключа другого участника
    void computeSharedSecret(long long otherPublicKey) {
        sharedSecret = modPow(otherPublicKey, privateKey, p);
        std::cout << "Вычислен общий секрет: " << sharedSecret << std::endl;
    }
    
    // Получить общий секрет
    long long getSharedSecret() const {
        return sharedSecret;
    }
    
    // Показать информацию об участнике
    void showInfo(const std::string& name) const {
        std::cout << "\n--- Информация об участнике " << name << " ---" << std::endl;
        std::cout << "Закрытый ключ: " << privateKey << std::endl;
        std::cout << "Открытый ключ: " << publicKey << std::endl;
        if (sharedSecret != 0) {
            std::cout << "Общий секрет: " << sharedSecret << std::endl;
        }
    }
};

int main() {
    setlocale(LC_ALL, "Russian");
    
    std::cout << "=========================================" << std::endl;
    std::cout << "    ПРОТОКОЛ ДИФФИ-ХЕЛЛМАНА    " << std::endl;
    std::cout << "=========================================" << std::endl;
    
    // Шаг 1: Выбор общих параметров (p и g)
    std::cout << "\n[Шаг 1] Выбор общих параметров:" << std::endl;
    
    // Для демонстрации используем небольшое простое число
    long long p, g;
    


    // Можно использовать предопределенные значения
    p = 23; // простое число
    g = 9;  // генератор (примитивный корень по модулю 23)


    
    std::cout << "Общее простое число p = " << p << std::endl;
    std::cout << "Общий генератор g = " << g << std::endl;
    
    // Проверка, что p простое
    if (!isPrime(p)) {
        std::cout << "Ошибка: p должно быть простым числом!" << std::endl;
        return 1;
    }
    
    // Шаг 2: Создание участников
    std::cout << "\n[Шаг 2] Создание участников и генерация ключей:" << std::endl;
    
    DiffieHellmanParticipant alice(p, g);
    DiffieHellmanParticipant bob(p, g);
    
    alice.showInfo("Алиса");
    bob.showInfo("Боб");
    
    // Шаг 3: Обмен открытыми ключами
    std::cout << "\n[Шаг 3] Обмен открытыми ключами:" << std::endl;
    std::cout << "Алиса отправляет Бобу свой открытый ключ: " << alice.getPublicKey() << std::endl;
    std::cout << "Боб отправляет Алисе свой открытый ключ: " << bob.getPublicKey() << std::endl;
    
    // Шаг 4: Вычисление общего секрета
    std::cout << "\n[Шаг 4] Вычисление общего секрета:" << std::endl;
    std::cout << "Алиса вычисляет общий секрет на основе ключа Боба:" << std::endl;
    alice.computeSharedSecret(bob.getPublicKey());
    
    std::cout << "\nБоб вычисляет общий секрет на основе ключа Алисы:" << std::endl;
    bob.computeSharedSecret(alice.getPublicKey());
    
    std::cout << "\n[Результат] Общие секреты должны совпадать:" << std::endl;
    std::cout << "Секрет Алисы: " << alice.getSharedSecret() << std::endl;
    std::cout << "Секрет Боба:   " << bob.getSharedSecret() << std::endl;
    
    if (alice.getSharedSecret() == bob.getSharedSecret()) {
        std::cout << "✓ Общий секрет успешно сгенерирован!" << std::endl;
    } else {
        std::cout << "✗ Ошибка: общие секреты не совпадают!" << std::endl;
        return 1;
    }
    
    // Шаг 5: Демонстрация симметричного шифрования
    std::cout << "\n=========================================" << std::endl;
    std::cout << "  ДЕМОНСТРАЦИЯ СИММЕТРИЧНОГО ШИФРОВАНИЯ  " << std::endl;
    std::cout << "=========================================" << std::endl;
    
    long long sharedKey = alice.getSharedSecret(); // или bob.getSharedSecret()
    std::cout << "Используется общий ключ: " << sharedKey << std::endl;
    
    std::string originalMessage = "Привет, Боб! Это секретное сообщение от Алисы.";
    std::cout << "\nОригинальное сообщение: \"" << originalMessage << "\"" << std::endl;
    
    // Алиса шифрует сообщение
    std::cout << "\n[Алиса] Шифрует сообщение..." << std::endl;
    std::string encryptedMessage = xorEncryptDecrypt(originalMessage, sharedKey);
    
    std::cout << "Зашифрованное сообщение (hex): ";
    for (unsigned char c : encryptedMessage) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << (static_cast<int>(c) & 0xFF) << " ";
    }
    std::cout << std::dec << std::endl;
    
    // Алиса отправляет зашифрованное сообщение Бобу
    std::cout << "\n[Канал связи] Алиса отправляет зашифрованное сообщение Бобу..." << std::endl;
    
    // Боб расшифровывает сообщение
    std::cout << "\n[Боб] Расшифровывает сообщение..." << std::endl;
    std::string decryptedMessage = xorEncryptDecrypt(encryptedMessage, sharedKey);
    std::cout << "Расшифрованное сообщение: \"" << decryptedMessage << "\"" << std::endl;
    
    if (originalMessage == decryptedMessage) {
        std::cout << "\n✓ Успех! Сообщение успешно расшифровано!" << std::endl;
    } else {
        std::cout << "\n✗ Ошибка расшифровки!" << std::endl;
    }
    
    // Дополнительная демонстрация: перехват сообщения злоумышленником
    std::cout << "\n=========================================" << std::endl;
    std::cout << "   ДЕМОНСТРАЦИЯ ПЕРЕХВАТА СООБЩЕНИЯ   " << std::endl;
    std::cout << "=========================================" << std::endl;
    std::cout << "Злоумышленник перехватывает зашифрованное сообщение," << std::endl;
    std::cout << "но у него нет общего ключа..." << std::endl;
    
    // Злоумышленник пытается подобрать ключ (неэффективно)
    std::cout << "\nПопытка расшифровки без знания ключа:" << std::endl;
    std::string wrongDecryption = xorEncryptDecrypt(encryptedMessage, 0); // случайный ключ
    std::cout << "Результат: \"" << wrongDecryption << "\"" << std::endl;
    
    return 0;
}