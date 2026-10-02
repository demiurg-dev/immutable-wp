<?php
/**
 * Plugin Name: e2e-probe
 * Description: iwp end-to-end probe, broken on purpose: a fatal error on every load, so deploy must roll back.
 * Version: 1.0.1
 */

if (!defined('ABSPATH')) {
	exit;
}

iwp_e2e_this_function_does_not_exist();
