<?php
/**
 * Plugin Name: Boreal Security
 * Plugin URI: https://borealform.com/boreal-security
 * Description: Evidence-first WordPress security scans, login throttling, audit history, and portable reports.
 * Version: 1.0.1
 * Requires at least: 5.8
 * Requires PHP: 7.4
 * Author: Borealform Studio
 * License: GPL-2.0-or-later
 * Text Domain: boreal-security
 */

defined( 'ABSPATH' ) || exit;
define( 'BOREAL_SECURITY_VERSION', '1.0.1' );
define( 'BOREAL_SECURITY_FILE', __FILE__ );
define( 'BOREAL_SECURITY_DIR', plugin_dir_path( __FILE__ ) );

require_once BOREAL_SECURITY_DIR . 'includes/class-database.php';
require_once BOREAL_SECURITY_DIR . 'includes/class-scanner.php';
require_once BOREAL_SECURITY_DIR . 'includes/class-login-guard.php';
require_once BOREAL_SECURITY_DIR . 'includes/class-admin.php';
require_once BOREAL_SECURITY_DIR . 'includes/class-integrations.php';

register_activation_hook( __FILE__, array( 'Boreal_Security_Database', 'install' ) );

function boreal_security_init() {
	Boreal_Security_Database::maybe_upgrade();
	( new Boreal_Security_Login_Guard() )->init();
	( new Boreal_Security_Integrations() )->init();
	if ( is_admin() ) {
		( new Boreal_Security_Admin() )->init();
	}
}
add_action( 'plugins_loaded', 'boreal_security_init' );

function boreal_security_audit( $action, $details = array() ) {
	global $wpdb;
	$wpdb->insert(
		Boreal_Security_Database::table( 'audit' ),
		array(
			'created_at' => current_time( 'mysql', true ),
			'user_id'    => get_current_user_id(),
			'action'     => sanitize_key( $action ),
			'details'    => wp_json_encode( $details ),
		),
		array( '%s', '%d', '%s', '%s' )
	);
}
