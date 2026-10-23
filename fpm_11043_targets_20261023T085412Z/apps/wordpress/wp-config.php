<?php
define('DB_NAME', 'wp');
define('DB_USER', 'wp');
define('DB_PASSWORD', 'wppassw0rd');
define('DB_HOST', 't11043-db:3306');
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', '');
define('AUTH_KEY', '89ca12d565120eddd0265ff15df4552a0a31166ec82e070a9fecc0b5dc7a671e');
define('SECURE_AUTH_KEY', '1402c5b70bfaa6b61dfa029b1b3841e6cd8c3cfc2ef820916d4f2a0202ee0eb9');
define('LOGGED_IN_KEY', '89ca12d565120eddd0265ff15df4552a0a31166ec82e070a9fecc0b5dc7a671e');
define('NONCE_KEY', '1402c5b70bfaa6b61dfa029b1b3841e6cd8c3cfc2ef820916d4f2a0202ee0eb9');
define('AUTH_SALT', '1402c5b70bfaa6b61dfa029b1b3841e6cd8c3cfc2ef820916d4f2a0202ee0eb9');
define('SECURE_AUTH_SALT', '89ca12d565120eddd0265ff15df4552a0a31166ec82e070a9fecc0b5dc7a671e');
define('LOGGED_IN_SALT', '1402c5b70bfaa6b61dfa029b1b3841e6cd8c3cfc2ef820916d4f2a0202ee0eb9');
define('NONCE_SALT', '89ca12d565120eddd0265ff15df4552a0a31166ec82e070a9fecc0b5dc7a671e');
$table_prefix = 'wp_';
define('WP_DEBUG', false);
if (isset($_SERVER['HTTP_HOST'])) {
    define('WP_HOME', 'http://'.$_SERVER['HTTP_HOST']);
    define('WP_SITEURL', 'http://'.$_SERVER['HTTP_HOST']);
}
if (!defined('ABSPATH')) define('ABSPATH', __DIR__ . '/');
require_once ABSPATH . 'wp-settings.php';
