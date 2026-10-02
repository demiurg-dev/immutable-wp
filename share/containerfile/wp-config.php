<?php
// iwp generic wp-config.php (identical for every site). Secrets come from podman secrets,
// site settings from /etc/iwp/wp-config.site.php. Do not edit inside the image.

// /run/secrets/iwp-db format: one KEY=value per line (DB_NAME, DB_USER, DB_PASSWORD, DB_HOST,
// DB_PREFIX); the value is taken verbatim to the end of the line (no quoting, no comments
// after it). Empty lines and lines starting with # are ignored.

function iwp_fail( $detail ) {
	error_log( 'iwp: ' . $detail );
	http_response_code( 500 );
	exit( 'Service unavailable' );
}

$iwp_lines = @file( '/run/secrets/iwp-db', FILE_IGNORE_NEW_LINES );
if ( false === $iwp_lines ) {
	iwp_fail( 'database secret missing or unreadable' );
}
$iwp_db = array();
foreach ( $iwp_lines as $iwp_line ) {
	if ( '' === $iwp_line || '#' === $iwp_line[0] ) {
		continue;
	}
	if ( "\r" === substr( $iwp_line, -1 ) ) {
		$iwp_line = substr( $iwp_line, 0, -1 );
	}
	if ( '' === $iwp_line ) {
		continue;
	}
	$iwp_kv = explode( '=', $iwp_line, 2 );
	if ( 2 !== count( $iwp_kv ) ) {
		iwp_fail( 'malformed line in database secret' );
	}
	$iwp_key = trim( $iwp_kv[0] );
	if ( ! in_array( $iwp_key, array( 'DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_HOST', 'DB_PREFIX' ), true ) ) {
		iwp_fail( 'unknown key in database secret' );
	}
	$iwp_db[ $iwp_key ] = $iwp_kv[1];
}
if ( ! isset( $iwp_db['DB_NAME'], $iwp_db['DB_USER'], $iwp_db['DB_PASSWORD'] ) ) {
	iwp_fail( 'database secret incomplete' );
}
define( 'DB_NAME', $iwp_db['DB_NAME'] );
define( 'DB_USER', $iwp_db['DB_USER'] );
define( 'DB_PASSWORD', $iwp_db['DB_PASSWORD'] );
define( 'DB_HOST', $iwp_db['DB_HOST'] ?? 'iwp-db-host' );
$table_prefix = $iwp_db['DB_PREFIX'] ?? 'wp_';
if ( ! preg_match( '/^[A-Za-z0-9_]+$/', $table_prefix ) ) {
	iwp_fail( 'invalid DB_PREFIX' );
}
unset( $iwp_db, $iwp_lines, $iwp_line, $iwp_kv, $iwp_key );

require '/run/secrets/iwp-salts';

define( 'DISALLOW_FILE_MODS', true );
define( 'DISALLOW_FILE_EDIT', true );
define( 'AUTOMATIC_UPDATER_DISABLED', true );
define( 'WP_AUTO_UPDATE_CORE', false );
define( 'DISABLE_WP_CRON', true );
define( 'WP_TEMP_DIR', '/tmp' );
define( 'FS_METHOD', 'direct' );

require '/etc/iwp/wp-config.site.php';

// Non-secret DB settings come from the site file ([database]); these are the defaults.
if ( ! defined( 'DB_CHARSET' ) ) {
	define( 'DB_CHARSET', 'utf8mb4' );
}
if ( ! defined( 'DB_COLLATE' ) ) {
	define( 'DB_COLLATE', '' );
}

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}
require_once ABSPATH . 'wp-settings.php';
