<?php
// login.php - Student Login with OTP Verification
// If account exists but is not activated → resend OTP and continue activation

define('ALLOWED_ENTRY_POINT', true);
session_start();

require_once 'admin_panel/config.php';
require_once 'admin_panel/auth_functions.php';

$error   = '';
$success = '';
$step    = 'credentials'; // 'credentials' or 'otp'

// If already logged in → redirect
if (isset($_SESSION['student_auth']) && !empty($_SESSION['student_auth']['student_id'])) {
    header("Location: student_dashboard.php");
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['login'])) {
        $email    = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';

        // Find student by email
        $stmt = $pdo->prepare("
            SELECT id, username, email, password_hash, is_active
            FROM students
            WHERE email = ?
        ");
        $stmt->execute([$email]);
        $student = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$student) {
            $error = "No account found with this email.";
        } elseif (!password_verify($password, $student['password_hash'])) {
            $error = "Incorrect password.";
        } else {
            // Account exists → check activation status
            if ($student['is_active'] == 0) {
                // ── Not activated → resend OTP and go to verification ────────
                $otp = generateOTP();
                if (saveOTP($student['id'], $otp)) {
                    [$ok, $msg] = sendOTPEmail($email, $student['username'], $otp);
                    if ($ok) {
                        $_SESSION['student_login_flow'] = [
                            'step'       => 'otp',
                            'student_id' => $student['id'],
                            'email'      => $email
                        ];
                        $step = 'otp';
                        $success = "Your account is registered but not yet activated.<br>"
                                 . "A <strong>new verification code</strong> has been sent to "
                                 . "<strong>" . htmlspecialchars($email) . "</strong>.<br>"
                                 . "Please check your inbox (and spam/junk folder).";
                    } else {
                        $error = "Failed to send activation code: " . $msg;
                    }
                } else {
                    $error = "Could not generate verification code.";
                }
            } else {
                // ── Already activated → normal login OTP flow ────────────────
                $otp = generateOTP();
                if (saveOTP($student['id'], $otp)) {
                    [$ok, $msg] = sendOTPEmail($email, $student['username'], $otp);
                    if ($ok) {
                        $_SESSION['student_login_flow'] = [
                            'step'       => 'otp',
                            'student_id' => $student['id'],
                            'email'      => $email
                        ];
                        $success = "Verification code sent to your email.";
                        $step    = 'otp';
                    } else {
                        $error = $msg ?: "Failed to send verification code.";
                    }
                } else {
                    $error = "Could not generate verification code.";
                }
            }
        }
    }

    // ── OTP verification (works for both activation and login) ──────────────
    elseif (isset($_POST['verify']) && !empty($_SESSION['student_login_flow']) && $_SESSION['student_login_flow']['step'] === 'otp') {
        $code = trim($_POST['code'] ?? '');
        if (strlen($code) === 6 && ctype_digit($code)) {
            if (verifyOTP($_SESSION['student_login_flow']['student_id'], $code)) {
                // Activate if it was pending
                $stmt = $pdo->prepare("
                    UPDATE students 
                    SET is_active = 1, updated_at = NOW()
                    WHERE id = ? AND is_active = 0
                ");
                $stmt->execute([$_SESSION['student_login_flow']['student_id']]);

                // Log in
                $_SESSION['student_auth'] = [
                    'student_id' => $_SESSION['student_login_flow']['student_id'],
                    'email'      => $_SESSION['student_login_flow']['email']
                ];
                unset($_SESSION['student_login_flow']);
                header("Location: student_dashboard.php");
                exit;
            } else {
                $error = "Invalid or expired code.";
            }
        } else {
            $error = "Please enter the 6-digit code.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Student Login – Eduxoria</title>
  <style>
    body {
      font-family: system-ui, sans-serif;
      max-width: 420px;
      margin: 3rem auto;
      padding: 0 1.5rem;
      line-height: 1.5;
    }
    h1, h2 { text-align: center; margin-bottom: 1.5rem; }
    .msg {
      padding: 1rem;
      border-radius: 8px;
      margin: 1rem 0;
      text-align: center;
    }
    .error   { background: #fee2e2; color: #991b1b; }
    .success { background: #ecfdf5; color: #065f46; }
    label { display: block; margin: 1.2rem 0 0.4rem; font-weight: 500; }
    input {
      width: 100%;
      padding: 0.8rem;
      border: 1px solid #d1d5db;
      border-radius: 6px;
      box-sizing: border-box;
      font-size: 1rem;
    }
    input:focus {
      border-color: #3b82f6;
      outline: none;
      box-shadow: 0 0 0 3px rgba(59,130,246,.1);
    }
    button {
      width: 100%;
      padding: 0.9rem;
      margin-top: 1.5rem;
      background: #2563eb;
      color: white;
      border: none;
      border-radius: 6px;
      font-size: 1.05rem;
      cursor: pointer;
    }
    button:hover { background: #1d4ed8; }
    .center { text-align: center; margin-top: 2rem; font-size: 0.95rem; }
    input[type="text"][pattern="\d{6}"] {
      font-size: 1.6rem;
      text-align: center;
      letter-spacing: 0.6em;
      font-family: monospace;
    }
  </style>
</head>
<body>

<h1>Student Login</h1>

<?php if ($error): ?><div class="msg error"><?= htmlspecialchars($error) ?></div><?php endif; ?>
<?php if ($success): ?><div class="msg success"><?= htmlspecialchars($success) ?></div><?php endif; ?>

<?php if ($step === 'credentials'): ?>

<form method="post">
  <label>Email</label>
  <input type="email" name="email" required autofocus>

  <label>Password</label>
  <input type="password" name="password" required>

  <button type="submit" name="login">Sign In</button>
</form>

<?php else: ?>

<h2>Verify Your Email</h2>
<p style="text-align:center;">
  Enter the 6-digit code sent to <strong><?= htmlspecialchars($_SESSION['student_login_flow']['email'] ?? 'your email') ?></strong>
</p>

<form method="post">
  <label>Verification Code</label>
  <input type="text" name="code"
         inputmode="numeric" pattern="\d{6}" maxlength="6" required
         placeholder="000000">

  <button type="submit" name="verify">Verify</button>
</form>

<?php endif; ?>

<div class="center">
  Don't have an account? <a href="student_enroll.php">Enroll Now</a>
</div>

</body>
</html>