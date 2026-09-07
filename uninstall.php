<?php
defined( 'WP_UNINSTALL_PLUGIN' ) || exit;
global $wpdb;
foreach ( array( 'scans', 'findings', 'audit' ) as $table ) {
	$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}boreal_security_{$table}" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
}
foreach ( array( 'boreal_security_db_version', 'boreal_security_login_limit', 'boreal_security_trusted_ip_hashes' ) as $option ) { delete_option( $option ); }
