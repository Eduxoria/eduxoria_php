<?php
// student_dashboard.php
// Checks if profile is complete → shows form if needed

define('ALLOWED_ENTRY_POINT', true);
session_start();

require_once 'admin_panel/config.php';
require_once 'admin_panel/auth_functions.php';

// Redirect if not logged in
if (!isset($_SESSION['student_auth']) || empty($_SESSION['student_auth']['student_id'])) {
    header("Location: login.php");
    exit;
}

$studentId = $_SESSION['student_auth']['student_id'];

// Fetch current student data
$stmt = $pdo->prepare("
    SELECT 
        username, email, full_name, contact_number, school_name,
        created_at
    FROM students
    WHERE id = ?
");
$stmt->execute([$studentId]);
$student = $stmt->fetch(PDO::FETCH_ASSOC) ?: [
    'username' => 'Student',
    'email'    => 'unknown',
    'full_name' => null,
    'contact_number' => null,
    'school_name' => null
];

// Check if profile is complete
$profileComplete = !empty($student['full_name']) &&
                   !empty($student['contact_number']) &&
                   !empty($student['school_name']);

// Handle profile form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_profile'])) {
    $fullName       = trim($_POST['full_name'] ?? '');
    $contactNumber  = trim($_POST['contact_number'] ?? '');
    $schoolName     = trim($_POST['school_name'] ?? '');

    if (strlen($fullName) < 3) {
        $error = "Full name must be at least 3 characters.";
    } elseif (!preg_match('/^[0-9+\-\s]{9,15}$/', $contactNumber)) {
        $error = "Please enter a valid contact number.";
    } elseif (strlen($schoolName) < 3) {
        $error = "School name must be at least 3 characters.";
    } else {
        $stmt = $pdo->prepare("
            UPDATE students 
            SET full_name = ?, 
                contact_number = ?, 
                school_name = ?,
                updated_at = NOW()
            WHERE id = ?
        ");
        if ($stmt->execute([$fullName, $contactNumber, $schoolName, $studentId])) {
            // Refresh data
            $student['full_name']       = $fullName;
            $student['contact_number']  = $contactNumber;
            $student['school_name']     = $schoolName;
            $profileComplete = true;
            $success = "Profile updated successfully!";
        } else {
            $error = "Failed to save profile. Please try again.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Student Dashboard – Eduxoria</title>
  <style>
    body {
      font-family: system-ui, sans-serif;
      margin: 0;
      padding: 0;
      background: #f8fafc;
      color: #1f2937;
    }
    .container { max-width: 1100px; margin: 0 auto; padding: 2rem 1.5rem; }
    header {
      background: #2563eb;
      color: white;
      padding: 1.5rem;
      text-align: center;
    }
    header h1 { margin: 0; font-size: 1.8rem; }
    .card {
      background: white;
      border-radius: 12px;
      padding: 2rem;
      margin: 2rem 0;
      box-shadow: 0 4px 12px rgba(0,0,0,0.08);
    }
    .card h2 { margin-top: 0; color: #1e40af; }
    .msg {
      padding: 1rem;
      border-radius: 8px;
      margin-bottom: 1.5rem;
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
    table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
    th, td { padding: 0.9rem; text-align: left; border-bottom: 1px solid #e5e7eb; }
    th { background: #f3f4f6; }
    .logout {
      display: inline-block;
      margin-top: 2rem;
      padding: 0.8rem 1.6rem;
      background: #ef4444;
      color: white;
      text-decoration: none;
      border-radius: 6px;
    }
    .logout:hover { background: #dc2626; }
  </style>
</head>
<body>

<header>
  <h1>Eduxoria Student Dashboard</h1>
</header>

<div class="container">

  <?php if (!$profileComplete): ?>
    <!-- Profile Completion Form -->
    <div class="card">
      <h2>Complete Your Profile</h2>
      <p style="color:#555;">Please fill in your details to continue using the platform.</p>

      <?php if (isset($error)): ?>
        <div class="msg error"><?= htmlspecialchars($error) ?></div>
      <?php endif; ?>
      <?php if (isset($success)): ?>
        <div class="msg success"><?= htmlspecialchars($success) ?></div>
      <?php endif; ?>

      <form method="post">
        <label>Full Name</label>
        <input type="text" name="full_name" value="<?= htmlspecialchars($student['full_name'] ?? '') ?>" required>

        <label>Contact Number</label>
        <input type="tel" name="contact_number" value="<?= htmlspecialchars($student['contact_number'] ?? '') ?>" required pattern="[0-9+\-\s]{9,15}">

        <label>School Name</label>
        <input type="text" name="school_name" value="<?= htmlspecialchars($student['school_name'] ?? '') ?>" required>

        <button type="submit" name="update_profile">Save & Continue</button>
      </form>
    </div>
  <?php else: ?>
    <!-- Normal Dashboard -->
    <div class="card">
      <h2>Welcome back, <?= htmlspecialchars($student['username']) ?>!</h2>
      <p>Email: <?= htmlspecialchars($student['email']) ?></p>
      <p>Member since: <?= date('d M Y', strtotime($student['created_at'])) ?></p>
    </div>

    <div class="card">
      <h3>Your Enrolled Modules</h3>
      <?php
      $stmt = $pdo->prepare("
          SELECT m.module_name, m.module_code, se.enrolled_at, se.status
          FROM student_enrollments se
          INNER JOIN modules m ON m.id = se.module_id
          WHERE se.student_id = ?
          ORDER BY se.enrolled_at DESC
      ");
      $stmt->execute([$studentId]);
      $enrollments = $stmt->fetchAll(PDO::FETCH_ASSOC);

      if ($enrollments):
      ?>
        <table>
          <thead>
            <tr>
              <th>Module Name</th>
              <th>Code</th>
              <th>Enrolled On</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            <?php foreach ($enrollments as $e): ?>
              <tr>
                <td><?= htmlspecialchars($e['module_name']) ?></td>
                <td><?= htmlspecialchars($e['module_code'] ?: '-') ?></td>
                <td><?= date('d M Y', strtotime($e['enrolled_at'])) ?></td>
                <td style="color: <?= $e['status'] === 'active' ? '#10b981' : '#ef4444' ?>">
                  <?= ucfirst($e['status']) ?>
                </td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      <?php else: ?>
        <p style="color:#6b7280;">You are not enrolled in any modules yet.</p>
      <?php endif; ?>
    </div>

    <a href="logout.php" class="logout">Logout</a>
  <?php endif; ?>

</div>

</body>
</html>