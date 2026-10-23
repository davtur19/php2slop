<?php
// Lab-only diagnostic entrypoint; not part of stock MediaWiki.
define( 'MW_ENTRY_POINT', 'probe' );
require __DIR__ . '/includes/WebStart.php';

header( 'Content-Type: text/plain; charset=utf-8' );
echo "PHP_VERSION=" . PHP_VERSION . "\n";
echo "session_module_name=" . session_module_name() . "\n";
echo "session_save_handler=" . ini_get( 'session.save_handler' ) . "\n";
echo "session_save_path=" . session_save_path() . "\n";
echo "session_serialize_handler=" . ini_get( 'session.serialize_handler' ) . "\n";
echo "session_auto_start=" . ini_get( 'session.auto_start' ) . "\n";
echo "session_use_cookies=" . ini_get( 'session.use_cookies' ) . "\n";
echo "session_status=" . session_status() . " (1=none,2=active,3=disabled)\n";
echo "session_id=" . session_id() . "\n";
echo "session_name=" . session_name() . "\n";
echo "PHPSessionHandler_installed=" . var_export( MediaWiki\Session\PHPSessionHandler::isInstalled(), true ) . "\n";
echo "PHPSessionHandler_enabled=" . var_export( MediaWiki\Session\PHPSessionHandler::isEnabled(), true ) . "\n";
$s = RequestContext::getMain()->getRequest()->getSession();
echo "mw_session_id=" . $s->getId() . "\n";
echo "mw_session_persistent=" . var_export( $s->isPersistent(), true ) . "\n";
echo "mw_session_remember=" . var_export( $s->shouldRememberUser(), true ) . "\n";
echo "session_data=" . var_export( $_SESSION ?? null, true ) . "\n";
