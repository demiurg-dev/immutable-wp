<?php
/**
 * Plugin Name: iwp
 * Description: Immutable WordPress hosting integration (managed by iwp; do not edit).
 */

// Code is read-only and updated by `iwp deploy`; hide the Site Health checks that expect
// in-dashboard updates and file modifications.
add_filter( 'site_status_tests', function ( $tests ) {
	unset( $tests['async']['background_updates'] );
	unset( $tests['direct']['plugin_theme_auto_updates'] );
	return $tests;
} );

// nginx never runs PHP from writable directories, but WordPress itself would `include` a file
// from one if the database told it to: the `stylesheet`/`template` options name the theme
// directory (`../uploads/x` leaves themes/), and a locale names the `.l10n.php` translation
// file. Code only ever comes from the read-only release, so anything PHP could write to is
// refused. A blocked theme is logged and leaves the site without a theme (wp-cli keeps working,
// so the option can be repaired).
function iwp_is_writable_location( $path ) {
	$real = realpath( $path );
	if ( false === $real ) {
		// Nothing there to include now; refuse anything that climbs out of its directory.
		return false !== strpos( str_replace( '\\', '/', $path ), '../' );
	}
	$dir = is_dir( $real ) ? $real : dirname( $real );
	return is_writable( $dir ) || is_writable( $real );
}

function iwp_guard_theme_directory( $dir ) {
	if ( ! is_string( $dir ) || ! iwp_is_writable_location( $dir ) ) {
		return $dir;
	}
	error_log( 'iwp: blocked theme directory ' . $dir . ' (writable location; check the stylesheet/template options)' );
	return WP_CONTENT_DIR . '/themes/.iwp-blocked';
}
add_filter( 'stylesheet_directory', 'iwp_guard_theme_directory', PHP_INT_MAX );
add_filter( 'template_directory', 'iwp_guard_theme_directory', PHP_INT_MAX );

function iwp_guard_translation_file( $file ) {
	if ( ! is_string( $file ) || '.php' !== strtolower( substr( $file, -4 ) ) || ! iwp_is_writable_location( $file ) ) {
		return $file;
	}
	error_log( 'iwp: blocked translation file ' . $file . ' (writable location)' );
	return WP_CONTENT_DIR . '/languages/.iwp-blocked.mo';
}
add_filter( 'load_translation_file', 'iwp_guard_translation_file', PHP_INT_MAX );
