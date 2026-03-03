#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <thread>
#include <future>
#include <chrono>
#include <iomanip>
#include <filesystem>
#include <mutex>

namespace fs = std::filesystem;

class RC4 {
private:
    std::vector<uint8_t> S;
    int i;
    int j;

    void swap(uint8_t& a, uint8_t& b) {
        uint8_t temp = a;
        a = b;
        b = temp;
    }

public:
    RC4() : i(0), j(0) {
        S.resize(256);
    }

    // Инициализация ключом
    void initialize(const std::vector<uint8_t>& key) {
        // Инициализация S-блока
        for (int i = 0; i < 256; i++) {
            S[i] = i;
        }

        // Перемешивание S-блока с ключом
        j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + S[i] + key[i % key.size()]) % 256;
            swap(S[i], S[j]);
        }

        // Сброс счетчиков
        i = 0;
        j = 0;
    }

    // Генерация следующего байта ключевого потока
    uint8_t nextByte() {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        swap(S[i], S[j]);
        
        int t = (S[i] + S[j]) % 256;
        return S[t];
    }

    // Шифрование/дешифрование данных (XOR с ключевым потоком)
    void processData(std::vector<uint8_t>& data) {
        for (auto& byte : data) {
            byte ^= nextByte();
        }
    }

    // Пропуск указанного количества байт
    void skipBytes(uint64_t count) {
        for (uint64_t k = 0; k < count; ++k) {
            nextByte();
        }
    }
};

// Класс для асинхронной обработки файлов
class FileProcessor {
private:
    size_t bufferSize;
    std::mutex coutMutex;  // Для синхронизации вывода

    // Функция для обработки части файла
    std::future<bool> processFilePart(const std::string& inputFile, 
                                      const std::string& outputFile,
                                      uint64_t startPos,
                                      uint64_t size,
                                      const std::vector<uint8_t>& key,
                                      uint64_t fileOffset,
                                      int partNumber) {
        return std::async(std::launch::async, [=, this]() {
            try {
                // Открываем файлы
                std::ifstream inFile(inputFile, std::ios::binary);
                std::ofstream outFile(outputFile, std::ios::binary | std::ios::in | std::ios::out);
                
                if (!inFile.is_open() || !outFile.is_open()) {
                    std::lock_guard<std::mutex> lock(coutMutex);
                    std::cerr << "  ❌ Часть " << partNumber << ": Ошибка открытия файлов" << std::endl;
                    return false;
                }

                // Позиционируемся на нужное место
                inFile.seekg(static_cast<std::streamoff>(startPos));
                outFile.seekp(static_cast<std::streamoff>(startPos));

                if (inFile.fail() || outFile.fail()) {
                    std::lock_guard<std::mutex> lock(coutMutex);
                    std::cerr << "  ❌ Часть " << partNumber << ": Ошибка позиционирования" << std::endl;
                    return false;
                }

                // Создаем экземпляр RC4 для этой части
                RC4 rc4;
                rc4.initialize(key);

                // Пропускаем байты до нужной позиции (для правильной синхронизации)
                rc4.skipBytes(fileOffset);

                // Буфер для чтения/записи
                std::vector<uint8_t> buffer(bufferSize);
                uint64_t remaining = size;
                
                // Показываем начало обработки части
                {
                    std::lock_guard<std::mutex> lock(coutMutex);
                    std::cout << "  ▶ Часть " << partNumber << ": начало (позиция " 
                              << startPos << ", размер " << size << " байт)" << std::endl;
                }

                // Обрабатываем данные
                while (remaining > 0) {
                    uint64_t bytesToRead = std::min(static_cast<uint64_t>(bufferSize), remaining);
                    
                    inFile.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(bytesToRead));
                    std::streamsize bytesRead = inFile.gcount();
                    
                    if (bytesRead > 0) {
                        // Изменяем размер буфера до фактически прочитанных байт
                        buffer.resize(static_cast<size_t>(bytesRead));
                        
                        // Шифруем/дешифруем
                        rc4.processData(buffer);
                        
                        // Записываем результат
                        outFile.write(reinterpret_cast<const char*>(buffer.data()), bytesRead);
                        
                        remaining -= static_cast<uint64_t>(bytesRead);
                        buffer.resize(bufferSize);
                    } else {
                        break;
                    }
                }

                {
                    std::lock_guard<std::mutex> lock(coutMutex);
                    std::cout << "  ✅ Часть " << partNumber << ": завершено" << std::endl;
                }
                
                return true;

            } catch (const std::exception& e) {
                std::lock_guard<std::mutex> lock(coutMutex);
                std::cerr << "  ❌ Часть " << partNumber << ": Ошибка - " << e.what() << std::endl;
                return false;
            }
        });
    }

public:
    FileProcessor(size_t bufSize = 64 * 1024) : bufferSize(bufSize) {} // 64KB буфер по умолчанию

    // Асинхронное шифрование/дешифрование файла
    bool processFileAsync(const std::string& inputFile, 
                          const std::string& outputFile, 
                          const std::vector<uint8_t>& key,
                          int numThreads = std::thread::hardware_concurrency()) {
        
        try {
            // Проверяем существование входного файла
            if (!fs::exists(inputFile)) {
                std::cerr << "❌ Входной файл не существует: " << inputFile << std::endl;
                return false;
            }

            // Получаем размер файла
            uint64_t fileSize = static_cast<uint64_t>(fs::file_size(inputFile));
            
            if (fileSize == 0) {
                std::cerr << "❌ Входной файл пуст" << std::endl;
                return false;
            }

            // Копируем входной файл в выходной (если это разные файлы)
            if (inputFile != outputFile) {
                // Создаем директорию для выходного файла, если её нет
                fs::path outputPath(outputFile);
                fs::path outputDir = outputPath.parent_path();
                if (!outputDir.empty() && !fs::exists(outputDir)) {
                    fs::create_directories(outputDir);
                }
                
                fs::copy_file(inputFile, outputFile, 
                            fs::copy_options::overwrite_existing);
                std::cout << "  📋 Создана копия файла для обработки" << std::endl;
            }

            // Определяем размер части для каждого потока
            uint64_t partSize = fileSize / numThreads;
            uint64_t remainder = fileSize % numThreads;

            std::vector<std::future<bool>> futures;
            uint64_t currentPos = 0;

            std::cout << "  🔄 Запуск " << numThreads << " потоков обработки..." << std::endl;

            // Запускаем асинхронную обработку каждой части
            for (int i = 0; i < numThreads; ++i) {
                uint64_t currentPartSize = partSize + (i < static_cast<int>(remainder) ? 1 : 0);
                
                if (currentPartSize > 0) {
                    auto future = processFilePart(inputFile, outputFile, 
                                                  currentPos, currentPartSize, 
                                                  key, currentPos, i + 1);
                    futures.push_back(std::move(future));
                    currentPos += currentPartSize;
                }
            }

            // Ожидаем завершения всех задач и проверяем результаты
            bool allSuccess = true;
            for (size_t i = 0; i < futures.size(); ++i) {
                try {
                    allSuccess = allSuccess && futures[i].get();
                } catch (const std::exception& e) {
                    std::cerr << "❌ Ошибка при ожидании задачи " << (i + 1) << ": " << e.what() << std::endl;
                    allSuccess = false;
                }
            }

            return allSuccess;

        } catch (const std::exception& e) {
            std::cerr << "❌ Ошибка при обработке файла: " << e.what() << std::endl;
            return false;
        }
    }
};

// Функция для создания имени выходного файла с _shifr
std::string createOutputFilename(const std::string& inputFilename) {
    fs::path inputPath(inputFilename);
    std::string stem = inputPath.stem().string();  // Имя файла без расширения
    std::string ext = inputPath.extension().string();  // Расширение файла
    
    // Создаем новое имя: имя_shifр.расширение
    std::string newFilename = stem + "_shifr" + ext;
    
    // Помещаем в папку output
    fs::path outputPath = fs::current_path() / "output" / newFilename;
    
    return outputPath.string();
}

// Функция для проверки существования папок
bool ensureDirectoriesExist() {
    try {
        // Создаем папку input, если её нет
        if (!fs::exists("input")) {
            fs::create_directory("input");
            std::cout << "📁 Создана папка input" << std::endl;
        }
        
        // Создаем папку output, если её нет
        if (!fs::exists("output")) {
            fs::create_directory("output");
            std::cout << "📁 Создана папка output" << std::endl;
        }
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "❌ Ошибка при создании папок: " << e.what() << std::endl;
        return false;
    }
}

// Функция для получения списка файлов в папке input
std::vector<std::string> getInputFiles() {
    std::vector<std::string> files;
    
    try {
        if (fs::exists("input") && fs::is_directory("input")) {
            for (const auto& entry : fs::directory_iterator("input")) {
                if (entry.is_regular_file()) {
                    files.push_back(entry.path().filename().string());
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "❌ Ошибка при чтении папки input: " << e.what() << std::endl;
    }
    
    return files;
}

// Функция для вывода прогресса
void showProgress(const std::string& inputFile, const std::string& outputFile) {
    std::cout << "\n🔐 Шифрование файла:" << std::endl;
    std::cout << "  📁 Входной файл: " << inputFile << std::endl;
    std::cout << "  📁 Выходной файл: " << outputFile << std::endl;
    
    if (fs::exists(inputFile)) {
        auto size = fs::file_size(inputFile);
        std::cout << "  📊 Размер файла: " << size << " байт";
        
        if (size > 1024) {
            std::cout << " (" << std::fixed << std::setprecision(2) 
                      << size / 1024.0 << " KB";
            
            if (size > 1024 * 1024) {
                std::cout << ", " << size / (1024.0 * 1024.0) << " MB";
            }
            
            if (size > 1024 * 1024 * 1024) {
                std::cout << ", " << size / (1024.0 * 1024.0 * 1024.0) << " GB";
            }
            
            std::cout << ")";
        }
        std::cout << std::endl;
    }
}

int main(int argc, char* argv[]) {
    setlocale(LC_ALL, "Russian");

    std::cout << "╔════════════════════════════════════════════╗" << std::endl;
    std::cout << "║     RC4 Шифрование/Дешифрование файлов    ║" << std::endl;
    std::cout << "║         Асинхронная версия v2.0           ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════╝" << std::endl;

    // Проверяем и создаем необходимые папки
    if (!ensureDirectoriesExist()) {
        return 1;
    }

    std::string inputFileName, key;
    int numThreads = std::thread::hardware_concurrency();
    bool decryptMode = false;

    // Обработка аргументов командной строки
    if (argc >= 3) {
        inputFileName = argv[1];
        key = argv[2];
        
        if (argc >= 4) {
            try {
                numThreads = std::stoi(argv[3]);
                if (numThreads < 1) numThreads = 1;
            } catch (...) {
                std::cerr << "⚠ Неверное количество потоков, используется автоопределение" << std::endl;
            }
        }
        
        if (argc >= 5 && std::string(argv[4]) == "decrypt") {
            decryptMode = true;
        }
    } else {
        // Интерактивный режим
        std::cout << "\n📋 Доступные файлы в папке input:" << std::endl;
        
        auto files = getInputFiles();
        if (files.empty()) {
            std::cout << "  Папка input пуста. Поместите файлы для шифрования в папку input." << std::endl;
            return 0;
        }
        
        for (size_t i = 0; i < files.size(); ++i) {
            std::cout << "  " << (i + 1) << ". " << files[i] << std::endl;
        }
        
        std::cout << "\nВведите название файла для шифрования: ";
        std::getline(std::cin, inputFileName);
        
        // Проверяем, не ввели ли номер
        try {
            int fileIndex = std::stoi(inputFileName);
            if (fileIndex > 0 && fileIndex <= static_cast<int>(files.size())) {
                inputFileName = files[fileIndex - 1];
            }
        } catch (...) {
            // Это не число, используем как есть
        }
        
        std::cout << "Введите ключ шифрования: ";
        std::getline(std::cin, key);
        
        std::cout << "Режим (1 - шифрование, 2 - дешифрование) [1]: ";
        std::string modeInput;
        std::getline(std::cin, modeInput);
        decryptMode = (modeInput == "2");
        
        std::cout << "Количество потоков (Enter - " << numThreads << "): ";
        std::string threadsInput;
        std::getline(std::cin, threadsInput);
        
        if (!threadsInput.empty()) {
            try {
                numThreads = std::stoi(threadsInput);
                if (numThreads < 1) numThreads = 1;
            } catch (...) {
                std::cout << "  ⚠ Используется значение по умолчанию: " << numThreads << std::endl;
            }
        }
    }

    // Формируем полные пути к файлам
    std::string inputFile = (fs::path("input") / inputFileName).string();
    
    std::string outputFile;
    if (decryptMode) {
        // Для дешифровки: убираем _shifr из имени
        fs::path inPath(inputFileName);
        std::string stem = inPath.stem().string();
        std::string ext = inPath.extension().string();
        
        // Проверяем, есть ли _shifr в имени
        size_t pos = stem.rfind("_shifr");
        if (pos != std::string::npos && pos == stem.length() - 6) {
            stem = stem.substr(0, pos);
        }
        
        std::string decryptedName = stem + "_decrypted" + ext;
        outputFile = (fs::path("output") / decryptedName).string();
    } else {
        outputFile = createOutputFilename(inputFileName);
    }

    // Проверяем существование входного файла
    if (!fs::exists(inputFile)) {
        std::cerr << "❌ Файл не найден: " << inputFile << std::endl;
        std::cout << "\nПроверьте наличие файла в папке input." << std::endl;
        return 1;
    }

    if (key.empty()) {
        std::cout << "  ⚠ Ключ пуст, шифрование небезопасно!" << std::endl;
    }

    // Создаем процессор файлов
    FileProcessor processor(64 * 1024); // 64KB буфер

    try {
        // Показываем информацию о процессе
        showProgress(inputFile, outputFile);
        
        std::cout << "  🔑 Ключ: \"" << key << "\" (длина: " << key.length() << " байт)" << std::endl;
        std::cout << "  ⚙ Потоков: " << numThreads << std::endl;
        std::cout << "  🔄 Режим: " << (decryptMode ? "Дешифрование" : "Шифрование") << std::endl;
        std::cout << std::endl;

        // Преобразуем ключ в вектор байт
        std::vector<uint8_t> keyBytes(key.begin(), key.end());

        // Замеряем время выполнения
        auto startTime = std::chrono::high_resolution_clock::now();

        // Выполняем асинхронную обработку
        bool success = processor.processFileAsync(inputFile, outputFile, keyBytes, numThreads);

        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

        std::cout << std::endl;
        if (success) {
            std::cout << "✅ Операция успешно завершена!" << std::endl;
            std::cout << "   ⏱ Время выполнения: " << duration.count() << " мс";
            
            if (duration.count() > 0) {
                auto fileSize = fs::file_size(outputFile);
                double speed = (static_cast<double>(fileSize) / 1024.0 / 1024.0) / 
                              (static_cast<double>(duration.count()) / 1000.0);
                std::cout << " (" << std::fixed << std::setprecision(2) << speed << " MB/s)";
            }
            std::cout << std::endl;
            
            // Проверяем размер выходного файла
            if (fs::exists(outputFile)) {
                auto outSize = fs::file_size(outputFile);
                std::cout << "   📊 Размер выходного файла: " << outSize << " байт" << std::endl;
                std::cout << "   📁 Файл сохранен в папке output" << std::endl;
            }
        } else {
            std::cerr << "❌ Ошибка при обработке файла!" << std::endl;
            return 1;
        }

    } catch (const std::exception& e) {
        std::cerr << "\n❌ Критическая ошибка: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}