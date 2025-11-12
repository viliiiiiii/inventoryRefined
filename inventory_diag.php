<?php
// inventory_get_diag.php — probes GET /inventory.php and prints the real error
declare(strict_types=1);
@ini_set('display_errors','1'); @ini_set('display_startup_errors','1'); @ini_set('log_errors','1'); @error_reporting(E_ALL);

set_exception_handler(function(Throwable $ex){
  http_response_code(500);
  echo "<h1>GET probe exception</h1>";
  echo "<pre style='white-space:pre-wrap'>".htmlspecialchars($ex->getMessage()."\n".$ex->getFile().":".$ex->getLine()."\n\n".$ex->getTraceAsString())."</pre>";
  exit;
});
set_error_handler(function($severity, $message, $file, $line){
  if (!(error_reporting() & $severity)) return false;
  throw new ErrorException($message, 0, $severity, $file, $line);
});

// Force index action (same as visiting inventory.php)
$_GET['action'] = $_GET['action'] ?? 'index';

require_once __DIR__.'/config.php';
require_once __DIR__.'/helpers.php';

// We're logged in (coming from profile), but if require_login() does something special,
// we still let it run naturally inside inventory.php.

ob_start();
include __DIR__.'/inventory.php';
$out = ob_get_clean();

// If inventory.php called exit() after rendering, we never get here, but on success we do:
if ($out) {
  header('Content-Type: text/html; charset=utf-8');
  echo $out;
}
