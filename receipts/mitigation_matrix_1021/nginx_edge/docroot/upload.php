<?php
// legitimate small upload target for lane F / N1 sanity
header('Content-Type: text/plain');
$out = ['ok' => false];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_FILES['file']) && is_array($_FILES['file'])) {
        $f = $_FILES['file'];
        if ($f['error'] === UPLOAD_ERR_OK) {
            $dir = '/tmp/opencode/nginx_mitigation_1021/run/uploads';
            @mkdir($dir, 0777, true);
            $dest = $dir . '/legit_' . getmypid() . '_' . bin2hex(random_bytes(4)) . '.bin';
            if (move_uploaded_file($f['tmp_name'], $dest)) {
                $out = ['ok' => true, 'size' => $f['size'], 'client_name' => $f['name'],
                        'stored' => $dest, 'sha256' => hash_file('sha256', $dest)];
            }
        }
        $out['upload_error'] = $f['error'];
    }
}
$out['mem_limit'] = ini_get('memory_limit');
$out['post_max_size'] = ini_get('post_max_size');
$out['upload_max_filesize'] = ini_get('upload_max_filesize');
$out['content_length'] = $_SERVER['CONTENT_LENGTH'] ?? null;
echo json_encode($out, JSON_PRETTY_PRINT), "\n";
