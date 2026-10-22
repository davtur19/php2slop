<?php
require '/tmp/opencode/research/wprealhex_20261022T011837Z/www/wordpress/wp-load.php';
global $wpdb;
$users = $wpdb->get_results("SELECT ID,user_login,user_email FROM {$wpdb->users} WHERE user_login LIKE 'umtest%' ORDER BY ID DESC LIMIT 5");
foreach ($users as $u) echo "user {$u->ID} {$u->user_login} {$u->user_email}\n";
$rows = $wpdb->get_results("SELECT option_name,LENGTH(option_value) len FROM {$wpdb->options} WHERE option_name LIKE '%transient%' AND option_value LIKE '%UMMARK%'");
foreach ($rows as $r) echo "transient {$r->option_name} len={$r->len}\n";
$rows = $wpdb->get_results("SELECT option_name,LENGTH(option_value) len FROM {$wpdb->options} WHERE option_name LIKE '%um_%' ORDER BY option_id DESC LIMIT 10");
foreach ($rows as $r) echo "opt {$r->option_name} len={$r->len}\n";
