<?php
defined( 'ABSPATH' ) || exit;

class Boreal_Security_Integrations {
	public function init() {
		add_filter( 'site_status_tests', array( $this, 'site_health' ) );
		if ( defined( 'WP_CLI' ) && WP_CLI ) { WP_CLI::add_command( 'boreal-security', array( $this, 'cli' ) ); }
	}
	public function site_health( $tests ) {
		$tests['direct']['boreal_security_scan'] = array( 'label' => __( 'Boreal Security scan status', 'boreal-security' ), 'test' => array( $this, 'health_test' ) );
		return $tests;
	}
	public function health_test() {
		global $wpdb;
		$scan = $wpdb->get_row( 'SELECT * FROM ' . Boreal_Security_Database::table( 'scans' ) . ' ORDER BY id DESC LIMIT 1' ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		$good = $scan && 'complete' === $scan->status;
		return array( 'label' => $good ? __( 'The latest Boreal Security scan completed', 'boreal-security' ) : __( 'No completed Boreal Security scan is available', 'boreal-security' ), 'status' => $good ? 'good' : 'recommended', 'badge' => array( 'label' => 'Security', 'color' => 'blue' ), 'description' => '<p>' . esc_html( $scan ? 'Latest status: ' . $scan->status : 'Run an explicit scan from the Boreal Security dashboard.' ) . '</p>', 'test' => 'boreal_security_scan' );
	}
	public function cli( $args, $assoc ) {
		$scanner = new Boreal_Security_Scanner();
		$id = $scanner->start();
		do {
			$result = $scanner->batch( $id );
			if ( is_wp_error( $result ) ) { WP_CLI::error( $result->get_error_message() ); }
			WP_CLI::log( 'Phase: ' . $result['phase'] );
		} while ( ! $result['done'] );
		WP_CLI::success( 'Scan ' . $id . ' completed.' );
	}
}
