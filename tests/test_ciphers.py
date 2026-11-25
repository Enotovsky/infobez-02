"""Проверки координат Полибия, обратимости и консольного меню."""

import os
from pathlib import Path
import subprocess
import sys
import unittest

from main import polybius_decrypt, polybius_encrypt, vigenere_decrypt, vigenere_encrypt


class PolybiusTests(unittest.TestCase):
    def test_known_coordinates(self):
        self.assertEqual(polybius_encrypt("HELLO", "en"), "22 15 26 26 33")
        self.assertEqual(polybius_decrypt("22 15 26 26 33", "en"), "HELLO")
        self.assertEqual(polybius_encrypt("ЁЖ Я", "ru"), "21 22 / 63")
        self.assertEqual(polybius_decrypt("21 22 / 63", "ru"), "ЁЖ Я")
        self.assertEqual(polybius_encrypt("IJ", "en"), "23 24")

    def test_every_letter_has_a_distinct_cell(self):
        for language, alphabet in (
            ("en", "abcdefghijklmnopqrstuvwxyz"),
            ("ru", "абвгдеёжзийклмнопрстуфхцчшщъыьэюя"),
        ):
            with self.subTest(language=language):
                encrypted = polybius_encrypt(alphabet, language)
                self.assertEqual(len(set(encrypted.split())), len(alphabet))
                self.assertEqual(polybius_decrypt(encrypted, language), alphabet.upper())

    def test_nonletters_and_spaces_round_trip(self):
        for message, language in (
            ("Hello, 11 / U+0021! \\ []\t\n😀", "en"),
            ("  Привет, ёж! 123  ", "ru"),
            ("", "ru"),
            ("   ", "en"),
        ):
            with self.subTest(message=message):
                encrypted = polybius_encrypt(message, language)
                self.assertEqual(polybius_decrypt(encrypted, language), message.upper())
        self.assertEqual(polybius_encrypt("1/!", "en"), "U+0031 U+002F U+0021")

    def test_invalid_inputs(self):
        for message, language in (("Hello", "ru"), ("Привет", "en"), ("aя", "en"), ("é", "en")):
            with self.subTest(message=message), self.assertRaises(ValueError):
                polybius_encrypt(message, language)
        for transform in (polybius_encrypt, polybius_decrypt):
            with self.assertRaises(ValueError):
                transform("", "de")
        for token, language in (
            ("53", "en"), ("64", "ru"), ("00", "ru"), ("77", "ru"),
            ("1", "ru"), ("111", "ru"), ("ab", "en"), ("１１", "en"),
            ("U+XYZ", "ru"), ("U+110000", "ru"), ("U+D800", "ru"),
            ("U+0041", "en"), ("U+002B1", "en"),
        ):
            with self.subTest(token=token), self.assertRaises(ValueError):
                polybius_decrypt(token, language)


class MenuAndRegressionTests(unittest.TestCase):
    def test_vigenere_example(self):
        self.assertEqual(vigenere_encrypt("ATTACK AT DAWN", "LEMON"), "LXFOPV EF RNHR")
        self.assertEqual(vigenere_decrypt("LXFOPV EF RNHR", "LEMON"), "ATTACK AT DAWN")
        message = "Привет, Ёж! 123"
        self.assertEqual(vigenere_decrypt(vigenere_encrypt(message, "ключ"), "ключ"), message)

    def test_menu(self):
        for stdin, expected in (
            ("1\n1\nATTACK AT DAWN\nLEMON\n", "LXFOPV EF RNHR"),
            ("1\n2\nLXFOPV EF RNHR\nLEMON\n", "ATTACK AT DAWN"),
            ("2\n1\nHELLO\nen\n", "22 15 26 26 33"),
            ("2\n2\n22 15 26 26 33\nen\n", "HELLO"),
            ("2\n1\nЁж!\nru\n", "21 22 U+0021"),
            ("2\n2\n21 22 U+0021\nru\n", "ЁЖ!"),
            ("3\n", "Ошибка:"),
            ("2\n3\n", "Ошибка:"),
            ("2\n2\n66\nru\n", "Ошибка:"),
            ("2\n1\nПривет\nen\n", "Ошибка:"),
        ):
            with self.subTest(stdin=stdin):
                result = subprocess.run(
                    [sys.executable, "main.py"], input=stdin, text=True,
                    encoding="utf-8", capture_output=True, check=True,
                    cwd=Path(__file__).resolve().parents[1],
                    env={**os.environ, "PYTHONIOENCODING": "utf-8"},
                )
                self.assertIn(expected, result.stdout)
                self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
