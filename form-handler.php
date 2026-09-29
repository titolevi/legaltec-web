<?php
/**
 * Manejador de formulario de contacto Legaltec
 *
 * Alternativa de terceros: FormSubmit (https://formsubmit.co) — requiere ajustar
 * CSP form-action y no se usa por defecto para mantener form-action 'self'.
 *
 * Uso:
 *  GET  ?action=csrf  → JSON { token }
 *  POST JSON/body     → envía correo o registra en logs/
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

session_start();

const MAIL_TO = 'comercial@legaltecnologias.pe';
const MAIL_SUBJECT = 'Nuevo contacto desde legaltecnologias.pe';
const LOG_DIR = __DIR__ . '/logs';

function json_response(array $payload, int $status = 200): void
{
    http_response_code($status);
    echo json_encode($payload, JSON_UNESCAPED_UNICODE);
    exit;
}

function generate_csrf_token(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validate_csrf(?string $token): bool
{
    if ($token === null || $token === '') {
        return false;
    }
    if (empty($_SESSION['csrf_token'])) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $token);
}

function sanitize_text(string $value, int $max = 2000): string
{
    $value = trim(strip_tags($value));
    $value = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $value) ?? '';
    if (mb_strlen($value) > $max) {
        $value = mb_substr($value, 0, $max);
    }
    return $value;
}

function is_valid_email(string $email): bool
{
    return (bool) filter_var($email, FILTER_VALIDATE_EMAIL);
}

function read_payload(): array
{
    $contentType = $_SERVER['CONTENT_TYPE'] ?? $_SERVER['HTTP_CONTENT_TYPE'] ?? '';
    if (stripos($contentType, 'application/json') !== false) {
        $raw = file_get_contents('php://input') ?: '';
        $data = json_decode($raw, true);
        return is_array($data) ? $data : [];
    }
    return $_POST;
}

function ensure_log_dir(): void
{
    if (!is_dir(LOG_DIR)) {
        @mkdir(LOG_DIR, 0750, true);
    }
}

function log_submission(array $data): bool
{
    ensure_log_dir();
    $line = json_encode(
        [
            'ts' => date('c'),
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'data' => $data,
        ],
        JSON_UNESCAPED_UNICODE
    );
    return (bool) @file_put_contents(LOG_DIR . '/contact.log', $line . PHP_EOL, FILE_APPEND | LOCK_EX);
}

function send_mail_message(array $data): bool
{
    $body = "Nuevo mensaje de contacto\n\n"
        . "Nombre: {$data['nombre']} {$data['apellido']}\n"
        . "Empresa: {$data['empresa']}\n"
        . "Email: {$data['email']}\n"
        . "Teléfono: {$data['telefono']}\n\n"
        . "Mensaje:\n{$data['mensaje']}\n";

    $headers = [
        'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=UTF-8',
        'From: Legaltec Web <noreply@legaltecnologias.pe>',
        'Reply-To: ' . $data['email'],
        'X-Mailer: PHP/' . phpversion(),
    ];

    return @mail(MAIL_TO, MAIL_SUBJECT, $body, implode("\r\n", $headers));
}

// --- CSRF token endpoint ---
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET' && ($_GET['action'] ?? '') === 'csrf') {
    json_response(['success' => true, 'token' => generate_csrf_token()]);
}

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    json_response(['success' => false, 'message' => 'Método no permitido.'], 405);
}

$payload = read_payload();

// Honeypot: rechazo silencioso (parece éxito)
$honeypot = sanitize_text((string) ($payload['website'] ?? ''), 100);
if ($honeypot !== '') {
    json_response(['success' => true, 'message' => 'Mensaje enviado correctamente. Te contactaremos pronto.']);
}

$csrf = $payload['csrf_token'] ?? ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null);
if (!validate_csrf(is_string($csrf) ? $csrf : null)) {
    json_response(['success' => false, 'message' => 'Token de seguridad inválido. Recarga la página e intenta de nuevo.'], 403);
}

$nombre = sanitize_text((string) ($payload['nombre'] ?? ''), 120);
$apellido = sanitize_text((string) ($payload['apellido'] ?? ''), 120);
$empresa = sanitize_text((string) ($payload['empresa'] ?? ''), 180);
$email = sanitize_text((string) ($payload['email'] ?? ''), 180);
$telefono = sanitize_text((string) ($payload['telefono'] ?? ''), 40);
$mensaje = sanitize_text((string) ($payload['mensaje'] ?? ''), 4000);

if ($nombre === '' || $email === '' || $mensaje === '') {
    json_response(['success' => false, 'message' => 'Completa los campos obligatorios.'], 422);
}

if (!is_valid_email($email)) {
    json_response(['success' => false, 'message' => 'El email corporativo no es válido.'], 422);
}

$data = [
    'nombre' => $nombre,
    'apellido' => $apellido,
    'empresa' => $empresa,
    'email' => $email,
    'telefono' => $telefono,
    'mensaje' => $mensaje,
];

$mailed = send_mail_message($data);
$logged = log_submission($data);

// Rotar token tras uso exitoso
unset($_SESSION['csrf_token']);
generate_csrf_token();

if ($mailed || $logged) {
    json_response([
        'success' => true,
        'message' => 'Mensaje enviado correctamente. Te contactaremos pronto.',
    ]);
}

json_response([
    'success' => false,
    'message' => 'No se pudo procesar el mensaje. Escríbenos a comercial@legaltecnologias.pe',
], 500);
