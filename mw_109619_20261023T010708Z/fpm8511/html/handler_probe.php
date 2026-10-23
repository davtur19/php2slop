<?php
// Lab-only session-handler diagnostic; not part of stock MediaWiki.
$log = '/tmp/opencode/research/mw_109619_20261023T010708Z/fpm8511/handler_probe.log';
function lp( $m ) {
	global $log;
	file_put_contents( $log, date( 'c' ) . ' ' . getmypid() . ' ' . $m . "\n", FILE_APPEND );
}
class H implements SessionHandlerInterface {
	public function open( $path, $name ): bool { lp( "open($path,$name)" ); return true; }
	public function close(): bool { lp( 'close' ); return true; }
	public function read( $id ): string|false { lp( "read($id)" ); return ''; }
	public function write( $id, $data ): bool { lp( "write($id," . strlen( $data ) . ")" ); return true; }
	public function destroy( $id ): bool { lp( "destroy($id)" ); return true; }
	public function gc( $max_lifetime ): int|false { lp( "gc($max_lifetime)" ); return 0; }
}
ini_set( 'session.save_handler', 'files' );
ini_set( 'session.save_path', '/tmp/opencode/research/mw_109619_20261023T010708Z/fpm8511/sessions' );
$ok = session_set_save_handler( new H(), true );
lp( 'set_save_handler=' . var_export( $ok, true ) . ' module=' . session_module_name() );
session_id( 'handlerprobe0123456789abcdef' );
$s = session_start();
lp( 'start=' . var_export( $s, true ) . ' status=' . session_status() . ' id=' . session_id() );
$_SESSION['probe'] = 'value';
session_write_close();
lp( 'after_close status=' . session_status() );
header( 'Content-Type: text/plain' );
echo "ok=$ok start=$s module=" . session_module_name() . " id=" . session_id() . "\n";
