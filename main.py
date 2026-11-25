"""Шифрование и расшифровка сообщений методами Виженера и Полибия."""

ALPHABETS = (
    "abcdefghijklmnopqrstuvwxyz",
    "абвгдеёжзийклмнопрстуфхцчшщъыьэюя",
)

POLYBIUS_ALPHABETS = {"en": ALPHABETS[0], "ru": ALPHABETS[1]}
POLYBIUS_SIZE = 6


def _vigenere(message: str, key: str, direction: int) -> str:
    """Преобразует текст, сохраняя регистр, пробелы и знаки препинания.

    Ключ и все буквы сообщения должны принадлежать одному алфавиту.
    Пробелы и знаки препинания не расходуют символы ключа.
    """
    key = key.lower()
    if not key:
        raise ValueError("Ключ не должен быть пустым.")

    alphabet = next(
        (letters for letters in ALPHABETS if all(c in letters for c in key)),
        None,
    )
    if alphabet is None:
        raise ValueError("Ключ должен содержать только русские или только английские буквы.")

    result = []
    key_index = 0
    for char in message:
        lower = char.lower()
        if lower in alphabet:
            shift = alphabet.index(key[key_index % len(key)])
            encrypted = alphabet[(alphabet.index(lower) + direction * shift) % len(alphabet)]
            result.append(encrypted.upper() if char.isupper() else encrypted)
            key_index += 1
        elif char.isalpha():
            raise ValueError("Буквы сообщения и ключа должны принадлежать одному алфавиту.")
        else:
            result.append(char)

    return "".join(result)


def vigenere_encrypt(message: str, key: str) -> str:
    """Шифрует сообщение с указанным ключом."""
    return _vigenere(message, key, 1)


def vigenere_decrypt(message: str, key: str) -> str:
    """Расшифровывает сообщение с тем же ключом, что при шифровании."""
    return _vigenere(message, key, -1)


def _polybius_alphabet(language: str) -> str:
    """Возвращает алфавит квадрата 6×6 для выбранного языка."""
    if language not in POLYBIUS_ALPHABETS:
        raise ValueError("Выберите язык ru (русский) или en (английский).")
    return POLYBIUS_ALPHABETS[language]


def polybius_encrypt(message: str, language: str = "ru") -> str:
    """Кодирует буквы координатами 11–66, пробелы — /, прочее — U+XXXX.

    Алфавит записан по строкам квадрата 6×6, нумерация начинается с 1.
    Регистр букв не сохраняется; ключ не требуется.
    """
    alphabet = _polybius_alphabet(language)
    result = []
    for char in message:
        lower = char.lower()
        if lower in alphabet:
            row, column = divmod(alphabet.index(lower), POLYBIUS_SIZE)
            result.append(f"{row + 1}{column + 1}")
        elif char.isalpha():
            raise ValueError("Буквы сообщения должны принадлежать выбранному алфавиту.")
        elif char == " ":
            result.append("/")
        else:
            result.append(f"U+{ord(char):04X}")
    return " ".join(result)


def polybius_decrypt(message: str, language: str = "ru") -> str:
    """Расшифровывает координаты Полибия; возвращает заглавные буквы."""
    alphabet = _polybius_alphabet(language)
    result = []
    for token in message.split():
        if token == "/":
            result.append(" ")
        elif (len(token) == 2
              and all(char in "123456" for char in token)):
            index = (int(token[0]) - 1) * POLYBIUS_SIZE + int(token[1]) - 1
            if index >= len(alphabet):
                raise ValueError(f"Клетка {token} пуста в выбранном квадрате.")
            result.append(alphabet[index].upper())
        elif token.startswith("U+"):
            digits = token[2:]
            if not 4 <= len(digits) <= 6 or any(
                char not in "0123456789abcdefABCDEF" for char in digits
            ):
                raise ValueError(f"Некорректный код символа: {token}.")
            try:
                char = chr(int(digits, 16))
            except ValueError:
                raise ValueError(f"Некорректный код символа: {token}.") from None
            if char.isalpha() or 0xD800 <= ord(char) <= 0xDFFF:
                raise ValueError(f"Код {token} не обозначает небуквенный символ.")
            result.append(char)
        else:
            raise ValueError(f"Некорректный код Полибия: {token}.")
    return "".join(result)


if __name__ == "__main__":
    try:
        method = input("Выберите метод (1 — Виженер, 2 — Полибий): ").strip()
        if method not in ("1", "2"):
            raise ValueError("Выберите метод 1 или 2.")
        mode = input("Выберите режим (1 — шифрование, 2 — расшифровка): ").strip()
        if mode not in ("1", "2"):
            raise ValueError("Выберите режим 1 или 2.")
        message = input("Введите сообщение: ")
        if method == "1":
            key = input("Введите ключ: ")
            transform = vigenere_encrypt if mode == "1" else vigenere_decrypt
            result = transform(message, key)
        else:
            language = input("Выберите язык (ru — русский, en — английский): ").strip().lower()
            transform = polybius_encrypt if mode == "1" else polybius_decrypt
            result = transform(message, language)
        label = "Зашифрованное сообщение:" if mode == "1" else "Расшифрованное сообщение:"
        print(label, result)
    except ValueError as error:
        print("Ошибка:", error)
