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
