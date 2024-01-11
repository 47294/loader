#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <link.h>

void execute_elf(const char *filename) {
    int fd = open(filename, O_RDONLY);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    // Определение размера файла
    off_t file_size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    // Чтение заголовка ELF-файла
    Elf64_Ehdr elf_header;
    if (read(fd, &elf_header, sizeof(elf_header)) != sizeof(elf_header)) {
        perror("read");
        close(fd);
        exit(EXIT_FAILURE);
    }

    // Проверка, что это действительно ELF-файл
    if (memcmp(elf_header.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Not an ELF file\n");
        close(fd);
        exit(EXIT_FAILURE);
    }

    // Определение размера секции кода
    Elf64_Shdr code_section_header;
    lseek(fd, elf_header.e_shoff + elf_header.e_shentsize * elf_header.e_shstrndx, SEEK_SET);
    read(fd, &code_section_header, sizeof(code_section_header));

    // Чтение содержимого секции кода
    void *code_buffer = mmap(NULL, code_section_header.sh_size, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, code_section_header.sh_offset);
    if (code_buffer == MAP_FAILED) {
        perror("mmap");
        close(fd);
        exit(EXIT_FAILURE);
    }

    // Получение информации о динамических библиотеках
    Elf64_Dyn *dynamic_section = NULL;
    for (int i = 0; i < elf_header.e_shnum; ++i) {
        Elf64_Shdr section_header;
        lseek(fd, elf_header.e_shoff + i * elf_header.e_shentsize, SEEK_SET);
        read(fd, &section_header, sizeof(section_header));

        if (section_header.sh_type == SHT_DYNAMIC) {
            dynamic_section = mmap(NULL, section_header.sh_size, PROT_READ, MAP_PRIVATE, fd, section_header.sh_offset);
            if (dynamic_section == MAP_FAILED) {
                perror("mmap");
                close(fd);
                exit(EXIT_FAILURE);
            }
            break;
        }
    }

    if (!dynamic_section) {
        fprintf(stderr, "No dynamic section found\n");
        munmap(code_buffer, code_section_header.sh_size);
        close(fd);
        exit(EXIT_FAILURE);
    }

    // Обработка зависимостей от библиотек
    for (Elf64_Dyn *entry = dynamic_section; entry->d_tag != DT_NULL; ++entry) {
        if (entry->d_tag == DT_NEEDED) {
            char *lib_name = (char *)(code_buffer + entry->d_un.d_val);
            printf("Needed library: %s\n", lib_name);

            // Здесь вы можете реализовать код для загрузки и обработки библиотек
            // ...

            // Пример: Загрузка библиотеки с помощью dlopen
            // void *lib_handle = dlopen(lib_name, RTLD_NOW);
            // if (!lib_handle) {
            //     fprintf(stderr, "Failed to load library: %s\n", dlerror());
            //     // Обработка ошибки
            //     // ...
            // }
        }
    }

    // Закрытие файла
    close(fd);

    // Выполнение кода
    void (*code_function)() = (void (*)()) code_buffer;
    code_function();

    // Освобождение памяти
    munmap(code_buffer, code_section_header.sh_size);
    munmap(dynamic_section, code_section_header.sh_size);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <elf_file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    execute_elf(argv[1]);

    return 0;
}
