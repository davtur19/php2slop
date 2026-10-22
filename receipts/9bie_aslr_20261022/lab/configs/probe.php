<?php
header('Content-Type: text/plain');
echo 'display_errors='.ini_get('display_errors')."\n";
echo 'memory_limit='.ini_get('memory_limit')."\n";
echo 'post_max_size='.ini_get('post_max_size')."\n";
echo 'max_input_vars='.ini_get('max_input_vars')."\n";
echo 'session.use_cookies='.ini_get('session.use_cookies')."\n";
echo 'session.use_strict_mode='.ini_get('session.use_strict_mode')."\n";
echo 'session.upload_progress.enabled='.ini_get('session.upload_progress.enabled')."\n";
echo 'session.save_path='.ini_get('session.save_path')."\n";
echo 'PHP='.PHP_VERSION."\n";
