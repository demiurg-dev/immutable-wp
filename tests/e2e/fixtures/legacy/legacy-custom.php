<?php
/**
 * Plugin Name: Legacy Custom
 * Description: e2e fixture: a custom (non-wordpress.org) plugin on the legacy site; adds X-IWP-E2E-Legacy to front-end responses.
 * Version: 1.0.0
 */
add_action( 'send_headers', function () {
	header( 'X-IWP-E2E-Legacy: legacy-custom-v1' );
} );
