<?php
// student_enroll.php - Student registration & OTP verification
// Updated: cleaner structure, safe transactions, better debugging
// Added: Gmail alias blocking in code only (no SQL changes required)

define('ALLOWED_ENTRY_POINT', true);
session_start();

require_once 'admin_panel/config.php';
require_once 'admin_panel/auth_functions.php';

// ── Configuration ─────────────────────────────────────────────────────────────
$debug_mode = true; // ← set to false in production

$error   = '';
$success = '';
$step    = 'form';

// CSRF protection
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// ── Email normalization helpers ───────────────────────────────────────────────
function normalizeEmail(string $email): string
{
    $email = trim(strtolower($email));

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return '';
    }

    [$local, $domain] = explode('@', $email, 2);

    // Gmail / Googlemail specific normalization
    if ($domain === 'gmail.com' || $domain === 'googlemail.com') {
        $domain = 'gmail.com';

        // Remove everything after +
        $local = preg_replace('/\+.*/', '', $local);

        // Gmail ignores dots
        $local = str_replace('.', '', $local);
    }

    return $local . '@' . $domain;
}

function getEmailDomain(string $email): string
{
    $email = trim(strtolower($email));
    if (!str_contains($email, '@')) {
        return '';
    }

    return substr(strrchr($email, '@'), 1);
}

function isGmailDomain(string $domain): bool
{
    return in_array($domain, ['gmail.com', 'googlemail.com'], true);
}

/**
 * Check if username or normalized email already exists
 * Code-only approach without DB schema changes
 */
function findExistingStudent(PDO $pdo, string $username, string $email): ?array
{
    $normalizedInput = normalizeEmail($email);
    $domain = getEmailDomain($email);

    // First check username exact match
    $stmt = $pdo->prepare("
        SELECT id, is_active, email, username
        FROM students
        WHERE username = ?
        LIMIT 1
    ");
    $stmt->execute([$username]);
    $existingByUsername = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($existingByUsername) {
        return $existingByUsername;
    }

    // Exact email match first
    $stmt = $pdo->prepare("
        SELECT id, is_active, email, username
        FROM students
        WHERE LOWER(email) = LOWER(?)
        LIMIT 1
    ");
    $stmt->execute([$email]);
    $existingByExactEmail = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($existingByExactEmail) {
        return $existingByExactEmail;
    }

    // For Gmail / Googlemail, search all Gmail-like candidates and compare in PHP
    if (isGmailDomain($domain)) {
        $stmt = $pdo->prepare("
            SELECT id, is_active, email, username
            FROM students
            WHERE LOWER(email) LIKE '%@gmail.com'
               OR LOWER(email) LIKE '%@googlemail.com'
        ");
        $stmt->execute();
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($rows as $row) {
            if (normalizeEmail($row['email']) === $normalizedInput) {
                return $row;
            }
        }
    } else {
        // For non-Gmail domains, exact lowercase compare is enough
        $stmt = $pdo->prepare("
            SELECT id, is_active, email, username
            FROM students
            WHERE LOWER(email) = LOWER(?)
            LIMIT 1
        ");
        $stmt->execute([$email]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($row) {
            return $row;
        }
    }

    return null;
}

// ── Load content types & modules ─────────────────────────────────────────────
$contentTypes = $pdo->query("
    SELECT id, type_name
    FROM content_types
    WHERE is_deleted = 0 AND status = 1
    ORDER BY type_name
")->fetchAll(PDO::FETCH_ASSOC) ?: [];

$modulesByType = [];
$stmt = $pdo->prepare("
    SELECT m.id, m.module_name, COALESCE(m.module_code, '') AS module_code, m.type_id
    FROM modules m
    INNER JOIN content_types t ON t.id = m.type_id
    WHERE m.is_deleted = 0 AND m.status = 1
      AND t.is_deleted = 0 AND t.status = 1
    ORDER BY m.module_name
");
$stmt->execute();
while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
    $tid = (string)$row['type_id'];
    $modulesByType[$tid][] = $row;
}
$modulesJson = json_encode($modulesByType, JSON_UNESCAPED_UNICODE);

// ── POST handling ─────────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (empty($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $error = "Security check failed. Please refresh the page and try again.";
    } else {
        // ── Registration attempt ─────────────────────────────────────────────
        if (isset($_POST['enroll'])) {
            $username   = trim($_POST['username']   ?? '');
            $email      = trim($_POST['email']      ?? '');
            $password   = $_POST['password']        ?? '';
            $confirm    = $_POST['confirm_password']?? '';
            $type_id    = (int)($_POST['type_id']   ?? 0);
            $module_id  = (int)($_POST['module_id'] ?? 0);

            $normalizedEmail = normalizeEmail($email);

            // Basic validation
            if (strlen($username) < 4) {
                $error = "Username must be at least 4 characters long.";
            } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $error = "Please enter a valid email address.";
            } elseif ($normalizedEmail === '') {
                $error = "Please enter a valid email address.";
            } elseif (strlen($password) < 6) {
                $error = "Password must be at least 6 characters long.";
            } elseif ($password !== $confirm) {
                $error = "Passwords do not match.";
            } elseif ($type_id <= 0) {
                $error = "Please select a student type.";
            } elseif ($module_id <= 0) {
                $error = "Please select a module.";
            } else {
                // Check for existing account using PHP normalization logic
                $existing = findExistingStudent($pdo, $username, $email);

                if ($existing) {
                    if ((int)$existing['is_active'] === 0) {
                        // ── Resend OTP for pending account ───────────────────────
                        $studentId    = $existing['id'];
                        $studentEmail = $existing['email'];

                        $newOtp = generateOTP();
                        if (saveOTP($studentId, $newOtp)) {
                            [$ok, $msg] = sendOTPEmail($studentEmail, $existing['username'], $newOtp);

                            if ($ok) {
                                $_SESSION['pending_enroll'] = [
                                    'student_id' => $studentId,
                                    'email'      => $studentEmail
                                ];
                                $step = 'otp';
                                $success = "We found your pending registration.<br>A new verification code has been sent to <strong>"
                                         . htmlspecialchars($studentEmail) . "</strong>.<br>Please check your inbox (including spam/junk).";
                            } else {
                                $error = "Failed to send new verification code: " . htmlspecialchars($msg);
                            }
                        } else {
                            $error = "Could not generate a new verification code.";
                        }
                    } else {
                        if (strcasecmp($existing['username'], $username) === 0) {
                            $error = "This username is already registered and active.";
                        } else {
                            $error = "This email is already registered and active.";
                        }
                    }
                } else {
                    // ── Brand new registration ───────────────────────────────────
                    try {
                        $pdo->beginTransaction();

                        $hash = password_hash($password, PASSWORD_DEFAULT);

                        // Insert student
                        $stmt = $pdo->prepare("
                            INSERT INTO students
                            (username, email, password_hash, preferred_content_type_id, is_active)
                            VALUES (?, ?, ?, ?, 0)
                        ");
                        $stmt->execute([$username, strtolower($email), $hash, $type_id]);
                        $studentId = $pdo->lastInsertId();

                        // Enroll in module
                        $stmt = $pdo->prepare("
                            INSERT INTO student_enrollments
                            (student_id, module_id, status)
                            VALUES (?, ?, 'active')
                        ");
                        $stmt->execute([$studentId, $module_id]);

                        $pdo->commit();

                        // Send OTP
                        $otp = generateOTP();
                        if (saveOTP($studentId, $otp)) {
                            [$ok, $msg] = sendOTPEmail(strtolower($email), $username, $otp);
                            if ($ok) {
                                $_SESSION['pending_enroll'] = [
                                    'student_id' => $studentId,
                                    'email'      => strtolower($email)
                                ];
                                $step = 'otp';
                                $success = "Registration successful!<br>A 6-digit verification code has been sent to your email.";
                            } else {
                                $error = "Registration completed but email failed: " . htmlspecialchars($msg);
                            }
                        } else {
                            $error = "Registration completed but could not generate verification code.";
                        }
                    } catch (Exception $e) {
                        if ($pdo->inTransaction()) {
                            $pdo->rollBack();
                        }

                        $errMsg = $e->getMessage();
                        error_log("Enrollment error: $errMsg\n" . $e->getTraceAsString());

                        if ($debug_mode) {
                            $error = "Registration failed: " . htmlspecialchars($errMsg);
                        } else {
                            $error = "Registration failed. Please try again later.";
                        }
                    }
                }
            }
        }

        // ── OTP Verification ──────────────────────────────────────────────────
        elseif (isset($_POST['verify']) && !empty($_SESSION['pending_enroll'])) {
            $code = trim($_POST['code'] ?? '');
            $studentId = $_SESSION['pending_enroll']['student_id'] ?? 0;

            if (strlen($code) === 6 && ctype_digit($code) && $studentId > 0) {
                if (verifyOTP($studentId, $code)) {
                    $stmt = $pdo->prepare("
                        UPDATE students
                        SET is_active = 1, updated_at = NOW()
                        WHERE id = ?
                    ");
                    $stmt->execute([$studentId]);

                    unset($_SESSION['pending_enroll']);
                    header("Location: login.php?enrolled=1");
                    exit;
                } else {
                    $error = "Invalid or expired verification code.";
                    $step = 'otp';
                }
            } else {
                $error = "Please enter a valid 6-digit code.";
                $step = 'otp';
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Student Enrollment – Eduxoria</title>
  <style>
    body { font-family:system-ui,sans-serif; max-width:480px; margin:2.5rem auto; padding:0 1.5rem; line-height:1.5; }
    h1 { text-align:center; margin-bottom:2rem; }
    .msg { padding:1rem; border-radius:8px; margin:1rem 0; text-align:center; }
    .error   { background:#fee2e2; color:#991b1b; border:1px solid #fecaca; }
    .success { background:#ecfdf5; color:#065f46; border:1px solid #a7f3d0; }
    label { display:block; margin:1.4rem 0 0.5rem; font-weight:500; }
    input, select { width:100%; padding:0.85rem; border:1px solid #d1d5db; border-radius:6px; box-sizing:border-box; font-size:1rem; }
    input:focus, select:focus { border-color:#3b82f6; outline:none; box-shadow:0 0 0 3px rgba(59,130,246,.15); }
    button { width:100%; padding:1rem; margin-top:1.8rem; background:#2563eb; color:white; border:none; border-radius:6px; font-size:1.1rem; cursor:pointer; font-weight:500; }
    button:hover:not(:disabled) { background:#1d4ed8; }
    button:disabled { background:#9ca3af; cursor:not-allowed; }
    .center { text-align:center; margin-top:2.2rem; font-size:0.95rem; }
    .otp-note { font-size:0.9rem; color:#555; text-align:center; margin-top:1.2rem; }
    .small { font-size:0.9rem; color:#666; }
  </style>
</head>
<body>

<h1>Student Enrollment</h1>

<?php if ($error):   ?><div class="msg error"><?= $error ?></div><?php endif; ?>
<?php if ($success): ?><div class="msg success"><?= $success ?></div><?php endif; ?>

<?php if ($step === 'form'): ?>

<form method="post" autocomplete="off">
  <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">

  <label for="username">Username</label>
  <input type="text" name="username" id="username" required minlength="4" autofocus>

  <label for="email">Email</label>
  <input type="email" name="email" id="email" required>

  <label for="password">Password</label>
  <input type="password" name="password" id="password" required minlength="6">

  <label for="confirm_password">Confirm Password</label>
  <input type="password" name="confirm_password" id="confirm_password" required minlength="6">

  <label for="typeSel">Student Type</label>
  <select name="type_id" id="typeSel" required onchange="showModules()">
    <option value="">— Select type —</option>
    <?php foreach ($contentTypes as $t): ?>
      <option value="<?= $t['id'] ?>"><?= htmlspecialchars($t['type_name']) ?></option>
    <?php endforeach; ?>
  </select>

  <div id="modArea" style="display:none; margin-top:1.3rem;">
    <label for="modSel">Module</label>
    <select name="module_id" id="modSel" required disabled>
      <option value="">— Select module —</option>
    </select>
    <div id="noMod" class="small" style="display:none; margin-top:0.7rem; color:#d97706;">
      No active modules available for this type.
    </div>
  </div>

  <button type="submit" name="enroll">Enroll</button>
</form>

<?php else: ?>

<h2 style="text-align:center; margin-bottom:1.5rem;">Verify Your Email</h2>
<p style="text-align:center; margin-bottom:1.8rem;">
  A code has been sent to <strong><?= htmlspecialchars($_SESSION['pending_enroll']['email'] ?? 'your email') ?></strong>
</p>

<form method="post">
  <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">

  <label for="code">6-digit Verification Code</label>
  <input type="text" name="code" id="code" inputmode="numeric" pattern="\d{6}" maxlength="6" required
         placeholder="000000" style="font-size:2rem; text-align:center; letter-spacing:0.8em; font-family:monospace;">

  <button type="submit" name="verify">Confirm</button>
</form>

<div class="otp-note">
  Didn't receive the code? Check your spam/junk folder.<br>
  If the problem persists, try registering again.
</div>

<?php endif; ?>

<div class="center">
  Already have an account? <a href="login.php">Sign in</a>
</div>

<script>
const modulesByType = <?= $modulesJson ?>;

function showModules() {
    const typeId = document.getElementById('typeSel').value;
    const modSel = document.getElementById('modSel');
    const area   = document.getElementById('modArea');
    const noMsg  = document.getElementById('noMod');

    modSel.innerHTML = '<option value="">— Select module —</option>';
    modSel.disabled = true;

    if (!typeId) {
        area.style.display = 'none';
        return;
    }

    area.style.display = 'block';
    const mods = Array.isArray(modulesByType[typeId]) ? modulesByType[typeId] : [];

    if (mods.length === 0) {
        noMsg.style.display = 'block';
    } else {
        noMsg.style.display = 'none';
        modSel.disabled = false;
        mods.forEach(m => {
            const opt = document.createElement('option');
            opt.value = m.id;
            opt.textContent = m.module_name + (m.module_code ? ` (${m.module_code})` : '');
            modSel.appendChild(opt);
        });
    }
}

// Auto-show modules if type is pre-selected (e.g. after failed validation)
if (document.getElementById('typeSel').value) {
    showModules();
}
</script>

</body>
</html>