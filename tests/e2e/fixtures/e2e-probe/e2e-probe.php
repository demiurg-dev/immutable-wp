<?php
/**
 * Plugin Name: e2e-probe
 * Description: iwp end-to-end probe. Marks every front-end response so the test can see which release is served.
 * Version: 1.0.0
 */

if (!defined('ABSPATH')) {
	exit;
}

const IWP_E2E_PROBE = 'iwp-e2e-probe-v1';

add_action('send_headers', function () {
	header('X-IWP-E2E-Probe: ' . IWP_E2E_PROBE);
});

add_action('wp_footer', function () {
	echo '<!-- ' . IWP_E2E_PROBE . ' -->';
});
