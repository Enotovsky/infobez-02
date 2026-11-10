"""Шифрование и расшифровка сообщений методом Виженера."""

ALPHABETS = (
    "abcdefghijklmnopqrstuvwxyz",
    "абвгдеёжзийклмнопрстуфхцчшщъыьэюя",
)


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


if __name__ == "__main__":
    try:
        mode = input("Выберите режим (1 — шифрование, 2 — расшифровка): ").strip()
        if mode not in ("1", "2"):
            raise ValueError("Выберите режим 1 или 2.")
        message = input("Введите сообщение: ")
        key = input("Введите ключ: ")
        if mode == "1":
            print("Зашифрованное сообщение:", vigenere_encrypt(message, key))
        else:
            print("Расшифрованное сообщение:", vigenere_decrypt(message, key))
    except ValueError as error:
        print("Ошибка:", error)
