<?php
// transfer_pdf.php
// View-only PDF for a given movement_id (does not upload to S3).
// Usage: transfer_pdf.php?movement_id=123

declare(strict_types=1);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/helpers.php';

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

$apps = get_pdo();
$core = get_pdo('core');

$movementId = isset($_GET['movement_id']) ? (int)$_GET['movement_id'] : 0;
if ($movementId <= 0) {
    http_response_code(400);
    echo 'Missing movement_id';
    exit;
}

$stmt = $apps->prepare(
    "SELECT m.*, i.name AS item_name, i.sku
     FROM inventory_movements m
     JOIN inventory_items i ON i.id = m.item_id
     WHERE m.id = ?"
);
$stmt->execute([$movementId]);
$m = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$m) {
    http_response_code(404);
    echo 'Movement not found';
    exit;
}

// sectors
$src = '-';
$tgt = '-';

if (!empty($m['source_sector_id'])) {
    $s = $core->prepare("SELECT name FROM sectors WHERE id = ?");
    $s->execute([(int)$m['source_sector_id']]);
    if ($row = $s->fetch(PDO::FETCH_ASSOC)) {
        $src = $row['name'];
    }
}
if (!empty($m['target_sector_id'])) {
    $s = $core->prepare("SELECT name FROM sectors WHERE id = ?");
    $s->execute([(int)$m['target_sector_id']]);
    if ($row = $s->fetch(PDO::FETCH_ASSOC)) {
        $tgt = $row['name'];
    }
}

// public sign link, if token exists
$token = null;
try {
    $st = $apps->prepare(
        "SELECT token
         FROM inventory_public_tokens
         WHERE movement_id = ? AND expires_at > NOW()
         ORDER BY id DESC LIMIT 1"
    );
    $st->execute([$movementId]);
    $row = $st->fetch(PDO::FETCH_ASSOC);
    if ($row) {
        $token = $row['token'];
    }
} catch (Throwable $e) {
    // table might not exist yet; ignore
}

if (defined('BASE_URL')) {
    $base = rtrim(BASE_URL, '/');
} else {
    $https  = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
    $scheme = $https ? 'https://' : 'http://';
    $host   = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $base   = rtrim($scheme . $host, '/');
}

$signUrl = $token
    ? $base . '/inventory.php?action=public_sign&token=' . urlencode($token)
    : '';

function pdf_escape_t(string $text): string {
    return strtr($text, [
        "\\" => "\\\\",
        "("  => "\\(",
        ")"  => "\\)",
        "\r" => " ",
        "\n" => " ",
    ]);
}

function build_transfer_pdf(array $m, string $src, string $tgt, string $signUrl): string {
    $ref  = 'TRF-' . str_pad((string)$m['id'], 6, '0', STR_PAD_LEFT);
    $when = $m['ts'] ?? '';
    $item = $m['item_name'] ?? '';
    $sku  = $m['sku'] ?? '';
    $dir  = strtoupper($m['direction'] ?? '');
    $amt  = (int)($m['amount'] ?? 0);
    $rsn  = $m['reason'] ?? '';

    $lines = [];
    $lines[] = "Inventory Transfer Form";
    $lines[] = "Reference: $ref";
    if ($when) $lines[] = "Date/Time: $when";
    $lines[] = "";
    $lines[] = "Item: $item";
    if ($sku !== '') $lines[] = "SKU: $sku";
    $lines[] = "Direction: $dir";
    $lines[] = "Quantity: $amt";
    $lines[] = "From sector: $src";
    $lines[] = "To sector:   $tgt";
    if ($rsn !== '') $lines[] = "Reason: $rsn";
    $lines[] = "";
    if ($signUrl !== '') {
        $lines[] = "Digital signing link:";
        $lines[] = $signUrl;
        $lines[] = "";
    }
    $lines[] = "Signatures:";
    $lines[] = "Source: _____________________________    Date: ____________";
    $lines[] = "Target: _____________________________    Date: ____________";

    $pageW = 595; $pageH = 842;
    $marginX = 50; $y = 780; $lineH = 16; $font = 11;

    $content = "";
    foreach ($lines as $line) {
        $text = pdf_escape_t($line);
        $content .= "BT /F1 $font Tf $marginX $y Td ($text) Tj ET\n";
        $y -= $lineH;
        if ($y < 60) break;
    }

    $pdf = "%PDF-1.4\n";
    $objs = [];
    $objs[] = "1 0 obj <</Type /Catalog /Pages 2 0 R>> endobj\n";
    $objs[] = "2 0 obj <</Type /Pages /Kids [3 0 R] /Count 1>> endobj\n";
    $objs[] = "4 0 obj <</Type /Font /Subtype /Type1 /BaseFont /Helvetica>> endobj\n";
    $len = strlen($content);
    $objs[] = "5 0 obj <</Length $len>> stream\n$content\nendstream endobj\n";
    $objs[] = "3 0 obj <</Type /Page /Parent 2 0 R /MediaBox [0 0 $pageW $pageH] /Resources <</Font <</F1 4 0 R>>>> /Contents 5 0 R>> endobj\n";

    $out = $pdf;
    $offsets = [0];
    foreach ($objs as $obj) {
        $offsets[] = strlen($out);
        $out .= $obj;
    }
    $xrefPos = strlen($out);
    $count = count($offsets);

    $out .= "xref\n0 $count\n";
    $out .= "0000000000 65535 f \n";
    for ($i = 1; $i < $count; $i++) {
        $out .= sprintf("%010d 00000 n \n", $offsets[$i]);
    }
    $out .= "trailer <</Size $count /Root 1 0 R>>\n";
    $out .= "startxref\n$xrefPos\n%%EOF";

    return $out;
}

$pdf = build_transfer_pdf($m, $src, $tgt, $signUrl);

header('Content-Type: application/pdf');
header('Content-Disposition: inline; filename="transfer-' . $movementId . '.pdf"');
header('Content-Length: ' . strlen($pdf));
echo $pdf;
