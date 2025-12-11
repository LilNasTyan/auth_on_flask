import re
from typing import Optional


class TextObfuscator:

    @staticmethod
    def obfuscate_phone(phone: str) -> str:
        #Обфускация номеров телефонов
        # +7 (123) 456-78-90
        pattern1 = r'(\+7\s\()(\d{3})(\)\s)(\d{3})(-\d{2}-\d{2})'
        replacement1 = r'\1***\3***\5'
        phone = re.sub(pattern1, replacement1, phone)

        # +7(123)456-78-90
        pattern1b = r'(\+\d\()(\d{3})(\))(\d{3})(-\d{2}-\d{2})'
        replacement1b = r'\1***\3***\5'
        phone = re.sub(pattern1b, replacement1b, phone)

        # 81234567890
        pattern2 = r'(8)(\d{3})(\d{3})(\d{4})'
        replacement2 = r'\1******\4'
        phone = re.sub(pattern2, replacement2, phone)

        # +79161234567
        pattern3 = r'(\+7)(\d{3})(\d{3})(\d{4})'
        replacement3 = r'\1*******\4'
        phone = re.sub(pattern3, replacement3, phone)

        # 8-123-456-78-90
        pattern4 = r'(8)(-\d{3})(-\d{3})(-\d{2}-\d{2})'
        replacement4 = r'\1-***-***\4'
        phone = re.sub(pattern4, replacement4, phone)

        # 8 (123) 456-78-90
        pattern5 = r'(8\s\()(\d{3})(\)\s)(\d{3})(-\d{2}-\d{2})'
        replacement5 = r'\1***\3***\5'
        phone = re.sub(pattern5, replacement5, phone)

        return phone

    @staticmethod
    def obfuscate_email(email: str) -> str:
        # Обфускация email адресов
        pattern = r'(\w)(\w*)(@\w+\.\w+)'
        replacement = r'\1***\3'
        return re.sub(pattern, replacement, email)

    @staticmethod
    def obfuscate_text(text: str) -> str:
        # Обфускация всего текста
        text = TextObfuscator.obfuscate_phone(text)
        text = TextObfuscator.obfuscate_email(text)
        return text

    @staticmethod
    def load_from_file(filepath: str) -> Optional[str]:
        # Загрузка текста из файла
        try:
            with open(filepath, 'r', encoding='utf-8') as file:
                return file.read()
        except Exception as e:
            print(f"Ошибка загрузки файла: {e}")
            return None

    @staticmethod
    def save_to_file(filepath: str, text: str) -> bool:
        # Сохранение текста в файл
        try:
            with open(filepath, 'w', encoding='utf-8') as file:
                file.write(text)
            return True
        except Exception as e:
            print(f"Ошибка сохранения файла: {e}")
            return False