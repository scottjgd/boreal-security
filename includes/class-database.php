<?php
defined( 'ABSPATH' ) || exit;

class Boreal_Security_Database {
	const VERSION = '3';

	public static function table( $name ) {
		global $wpdb;
		return $wpdb->prefix . 'boreal_security_' . $name;
	}

	public static function install() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$charset = $wpdb->get_charset_collate();
		dbDelta( 'CREATE TABLE ' . self::table( 'scans' ) . " (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			started_at datetime NOT NULL, finished_at datetime NULL,
			status varchar(20) NOT NULL, phase varchar(32) NOT NULL,
			scan_cursor longtext NULL, error_text text NULL,
			PRIMARY KEY (id), KEY status (status)
		) $charset;" );
		dbDelta( 'CREATE TABLE ' . self::table( 'findings' ) . " (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			scan_id bigint(20) unsigned NOT NULL, check_id varchar(100) NOT NULL,
			severity varchar(16) NOT NULL, title text NOT NULL, evidence longtext NOT NULL,
			confidence varchar(16) NOT NULL DEFAULT 'medium',
			impact text NOT NULL, remediation longtext NOT NULL,
			status varchar(16) NOT NULL DEFAULT 'open',
			created_at datetime NOT NULL,
			PRIMARY KEY (id), KEY scan_id (scan_id), KEY severity (severity)
		) $charset;" );
		dbDelta( 'CREATE TABLE ' . self::table( 'audit' ) . " (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			created_at datetime NOT NULL, user_id bigint(20) unsigned NOT NULL DEFAULT 0,
			action varchar(100) NOT NULL, details longtext NULL,
			PRIMARY KEY (id), KEY created_at (created_at)
		) $charset;" );
		if ( self::tables_exist() ) {
			update_option( 'boreal_security_db_version', self::VERSION, false );
		}
	}

	public static function maybe_upgrade() {
		if ( self::VERSION !== get_option( 'boreal_security_db_version' ) || ! self::tables_exist() ) {
			self::install();
		}
	}

	public static function tables_exist() {
		global $wpdb;
		foreach ( array( 'scans', 'findings', 'audit' ) as $name ) {
			$table = self::table( $name );
			$found = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			if ( $table !== $found ) {
				return false;
			}
		}
		return true;
	}
}
