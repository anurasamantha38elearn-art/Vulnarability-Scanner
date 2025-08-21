<?php
$result = "";
$vuln = "";
$scan_results = null;
$is_scanning = false;

if (isset($_POST['scan'])) {
  $target = trim($_POST['target']);

  if (!empty($target)) {
    $is_scanning = true;
    
    // Try different Python commands for Windows compatibility
    $python_commands = ['python', 'python3', 'py'];
    $python_script = null;
    
    foreach ($python_commands as $cmd) {
      $test_output = shell_exec("$cmd --version 2>&1");
      if (strpos($test_output, 'Python') !== false) {
        $python_script = "$cmd Backend/codexiovuln.py";
        break;
      }
    }
    
    if (!$python_script) {
      $result = "❌ Python not found. Please install Python and required dependencies.";
      $vuln = "Error: Python interpreter not available";
      $is_scanning = false;
    } else {
      // Call Python backend scanner
      $command = $python_script . " --url " . escapeshellarg($target) . " --ai-analysis --format json --level 2 2>&1";
      
      // Execute Python script
      $output = shell_exec($command);
      
      if ($output) {
        // Try to parse JSON output
        $json_start = strpos($output, '{');
        if ($json_start !== false) {
          $json_data = substr($output, $json_start);
          $scan_results = json_decode($json_data, true);
          
          if ($scan_results) {
            $result = "✅ Scan completed for: " . htmlspecialchars($target);
            $vuln = "🔍 Found " . count($scan_results['vulnerabilities']) . " vulnerabilities";
          } else {
            $result = "⚠️ Scan completed but couldn't parse results for: " . htmlspecialchars($target);
            $vuln = "❌ Error parsing scan results";
          }
        } else {
          $result = "⚠️ Scan completed for: " . htmlspecialchars($target);
          $vuln = "ℹ️ Raw output: " . htmlspecialchars(substr($output, 0, 200)) . "...";
        }
      } else {
        $result = "❌ Scan failed for: " . htmlspecialchars($target);
        $vuln = "Error: Could not execute scanner";
      }
    }
  } else {
    $result = "Please enter a valid input!";
  }
}
?>

<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Home | CODEXIO</title>
  <link rel="icon" href="Assets/WebLogo.png">
  <link rel="stylesheet" href="boostrap/bootstrap.css">
  <link rel="stylesheet" href="style.css">
  <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js"></script>
</head>

<body>

  <!-- navbar -->
  <nav class="navbar navbar-expand-lg navbar-dark bg-dark shadow-lg p-3 mb-4 bg-body-tertiary rounded fixed-top">
    <div class="container">
      <a class="navbar-brand d-flex align-items-center" href="#">
        <img src="Assets/WebLogo.png" alt="Logo" width="75" height="70" class="d-inline-block align-text">
        <strong class="fs-4 mb-1 d-flex align-items-center">CODEXIO</strong>
      </a>

      <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>

      <div class="collapse navbar-collapse" id="navbarSupportedContent">
        <ul class="navbar-nav ms-auto">
          <li class="nav-item">
            <a class="nav-link active" aria-current="page" href="#"> <i class="fa-solid fa-house"></i> Home</a>
          </li>

          <li class="nav-item dropdown">
            <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown" aria-expanded="false">
              User <i class="fa-solid fa-user"></i>
            </a>
            <ul class="dropdown-menu">
              <li><a class="dropdown-item" href="#">Profile</a></li>
            </ul>
          </li>
        </ul>
        <form class="d-flex" role="search">
          <input class="form-control me-2" type="search" placeholder="Search" aria-label="Search">
          <button class="btn btn-outline-success" type="submit">Search</button>
        </form>
        &nbsp; &nbsp;
        <form class="d-flex" role="search">
          <a class="btn btn-outline-danger" type="submit" href="#">Advanced Search</a>
        </form>
      </div>
    </div>
  </nav>
  <!-- navbar -->

  <br>

  <!-- content -->
  <div class="container mt-5 pt-5">

    <!-- input row -->
    <form method="POST" action="" class="row my-3">
      <div class="col-md-8">
        <input type="text" name="target" class="form-control" placeholder="Enter target URL or input" value="<?php echo isset($_POST['target']) ? htmlspecialchars($_POST['target']) : ''; ?>" required>
      </div>
      <div class="col-md-4">
        <button type="submit" name="scan" class="btn btn-success w-100" <?php echo $is_scanning ? 'disabled' : ''; ?>>
          <?php echo $is_scanning ? 'Scanning...' : 'Scan'; ?>
        </button>
      </div>
    </form>

    <!-- process + vuln areas -->
    <div class="row">
      <div class="col-md-6 text-bg-light p-3">
        <div class="process-area" id="processArea">
          <?php if ($is_scanning): ?>
            <div class="text-center">
              <h5>🔍 Scanning in Progress...</h5>
              <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Loading...</span>
              </div>
              <p class="mt-2"><?php echo $result; ?></p>
            </div>
          <?php else: ?>
            <div class="text-center">
              <h5>📋 Scan Results</h5>
              <p><?php echo $result ?: 'Enter a URL and click Scan to begin...'; ?></p>
              
              <?php if ($scan_results): ?>
                <div class="scan-summary">
                  <h6>📊 Scan Summary</h6>
                  <ul class="list-unstyled">
                    <li><strong>Target:</strong> <?php echo htmlspecialchars($scan_results['target'] ?? 'Unknown'); ?></li>
                    <li><strong>Timestamp:</strong> <?php echo htmlspecialchars($scan_results['timestamp'] ?? 'Unknown'); ?></li>
                    <li><strong>Scan Level:</strong> <?php echo htmlspecialchars($scan_results['scan_level'] ?? 'Unknown'); ?></li>
                    <li><strong>Total Issues:</strong> <?php echo count($scan_results['results'] ?? []); ?></li>
                    <li><strong>Vulnerabilities:</strong> <?php echo count($scan_results['vulnerabilities'] ?? []); ?></li>
                  </ul>
                </div>
              <?php endif; ?>
            </div>
          <?php endif; ?>
        </div>
      </div>
      
      <div class="col-md-6 text-bg-light p-3">
        <div class="vuln-area" id="vulnArea">
          <?php if ($scan_results && isset($scan_results['vulnerabilities'])): ?>
            <h5>🚨 Vulnerability Report</h5>
            <div class="vulnerability-list">
              <?php foreach ($scan_results['vulnerabilities'] as $index => $vuln_item): ?>
                <div class="vuln-item mb-3 p-2 border rounded">
                  <h6 class="text-danger"><?php echo htmlspecialchars($vuln_item['type']); ?> - <?php echo htmlspecialchars($vuln_item['severity'] ?? 'Unknown'); ?></h6>
                  <p><strong>URL:</strong> <?php echo htmlspecialchars($vuln_item['url']); ?></p>
                  <p><strong>Description:</strong> <?php echo htmlspecialchars($vuln_item['description']); ?></p>
                  <p><strong>Details:</strong> <?php echo htmlspecialchars($vuln_item['details'] ?? 'No details'); ?></p>
                  
                  <?php if (isset($vuln_item['ai_analysis'])): ?>
                    <div class="ai-analysis mt-2">
                      <h6 class="text-primary">🤖 AI Analysis & Solutions</h6>
                      <div class="ai-content">
                        <?php echo nl2br(htmlspecialchars($vuln_item['ai_analysis'])); ?>
                      </div>
                    </div>
                  <?php endif; ?>
                </div>
              <?php endforeach; ?>
            </div>
          <?php else: ?>
            <div class="text-center">
              <h5>🚨 Vulnerabilities</h5>
              <p><?php echo $vuln ?: 'No vulnerabilities found yet...'; ?></p>
            </div>
          <?php endif; ?>
        </div>
        
        <?php if ($scan_results && isset($scan_results['vulnerabilities'])): ?>
          <button class="btn btn-primary print-btn w-100" onclick="generatePDF()">
            📄 Generate PDF Report
          </button>
        <?php endif; ?>
      </div>
    </div>

    <script src="boostrap/bootstrap.bundle.min.js"></script>
    <script src="script.js"></script>

    <footer class="container-fluid text-center text-md-start">
      <div class="fixed-bottom col-12 text-center mb-4">
        &copy;2025 Copyright: <a class="text-reset fw-bold" href="#">CODEXIO™ All Rights Reserved</a>
      </div>
    </footer>

</body>
</html>