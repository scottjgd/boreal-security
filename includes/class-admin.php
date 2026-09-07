<?php
defined( 'ABSPATH' ) || exit;

class Boreal_Security_Admin {
	public function init() {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'wp_ajax_boreal_security_start', array( $this, 'ajax_start' ) );
		add_action( 'wp_ajax_boreal_security_batch', array( $this, 'ajax_batch' ) );
		add_action( 'admin_post_boreal_security_export', array( $this, 'export' ) );
		add_action( 'admin_post_boreal_security_settings', array( $this, 'settings' ) );
	}

	public function menu() {
		add_menu_page( __( 'Boreal Security', 'boreal-security' ), __( 'Boreal Security', 'boreal-security' ), 'manage_options', 'boreal-security', array( $this, 'page' ), 'dashicons-shield-alt' );
		foreach ( array( 'findings' => 'Findings', 'history' => 'History', 'audit' => 'Audit Log', 'settings' => 'Settings' ) as $slug => $label ) {
			add_submenu_page( 'boreal-security', $label, $label, 'manage_options', 'boreal-security-' . $slug, array( $this, 'page' ) );
		}
	}

	private function authorize_ajax() {
		check_ajax_referer( 'boreal_security_scan', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) { wp_send_json_error( array( 'message' => __( 'Permission denied.', 'boreal-security' ) ), 403 ); }
	}

	public function ajax_start() {
		$this->authorize_ajax();
		$scan_id = ( new Boreal_Security_Scanner() )->start();
		if ( is_wp_error( $scan_id ) ) { wp_send_json_error( array( 'message' => $scan_id->get_error_message() ), 500 ); }
		wp_send_json_success( array( 'scan_id' => $scan_id ) );
	}

	public function ajax_batch() {
		$this->authorize_ajax();
		$id = isset( $_POST['scan_id'] ) ? absint( $_POST['scan_id'] ) : 0;
		$result = ( new Boreal_Security_Scanner() )->batch( $id );
		if ( is_wp_error( $result ) ) { wp_send_json_error( array( 'message' => $result->get_error_message() ), 500 ); }
		wp_send_json_success( $result );
	}

	public function page() {
		if ( ! current_user_can( 'manage_options' ) ) { return; }
		global $wpdb;
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : 'boreal-security';
		$scans = $wpdb->get_results( 'SELECT * FROM ' . Boreal_Security_Database::table( 'scans' ) . ' ORDER BY id DESC LIMIT 50' ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		$findings = $wpdb->get_results( 'SELECT * FROM ' . Boreal_Security_Database::table( 'findings' ) . ' ORDER BY id DESC LIMIT 200' ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		$audit = $wpdb->get_results( 'SELECT * FROM ' . Boreal_Security_Database::table( 'audit' ) . ' ORDER BY id DESC LIMIT 200' ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		echo '<div class="wrap"><h1>' . esc_html__( 'Boreal Security', 'boreal-security' ) . '</h1>';
		if ( 'boreal-security-settings' === $page ) {
			$this->settings_page();
		} elseif ( 'boreal-security-findings' === $page ) {
			$this->findings_table( $findings );
		} elseif ( 'boreal-security-history' === $page ) {
			$this->history_table( $scans );
		} elseif ( 'boreal-security-audit' === $page ) {
			echo '<table class="widefat striped"><thead><tr><th>Time (UTC)</th><th>User</th><th>Action</th><th>Details</th></tr></thead><tbody>';
			foreach ( $audit as $row ) {
				echo '<tr><td>' . esc_html( $row->created_at ) . '</td><td>' . absint( $row->user_id ) . '</td><td>' . esc_html( $row->action ) . '</td><td><pre>' . esc_html( $row->details ) . '</pre></td></tr>';
			}
			echo '</tbody></table>';
		} else {
			echo '<p>' . esc_html__( 'Scans are explicit, bounded, resumable, and retain evidence. A failed check is never reported as clean.', 'boreal-security' ) . '</p><button id="boreal-scan" class="button button-primary">' . esc_html__( 'Run manual scan', 'boreal-security' ) . '</button><p id="boreal-status" aria-live="polite"></p>';
			if ( ! empty( $scans ) && 'complete' === $scans[0]->status ) {
				$latest_findings = array_filter( $findings, function( $finding ) use ( $scans ) {
					return (int) $finding->scan_id === (int) $scans[0]->id;
				} );
				$deductions = array( 'critical' => 25, 'high' => 15, 'medium' => 7, 'error' => 5, 'info' => 0 );
				$score = 100;
				foreach ( $latest_findings as $finding ) {
					$score -= isset( $deductions[ $finding->severity ] ) ? $deductions[ $finding->severity ] : 5;
				}
				echo '<div class="notice notice-info inline"><p><strong>' . esc_html__( 'Latest evidence score:', 'boreal-security' ) . ' ' . max( 0, $score ) . '/100</strong> ' . esc_html__( 'This prioritization score is not a guarantee, certification, or clean bill of health.', 'boreal-security' ) . '</p></div>';
			}
			$this->findings_table( array_slice( $findings, 0, 20 ) );
			$this->script();
		}
		echo '</div>';
	}

	private function findings_table( $rows ) {
		$base = wp_nonce_url( admin_url( 'admin-post.php?action=boreal_security_export&format=' ), 'boreal_security_export' );
		echo '<p><a class="button" href="' . esc_url( $base . 'json' ) . '">JSON</a> <a class="button" href="' . esc_url( $base . 'csv' ) . '">CSV</a></p><table class="widefat striped"><thead><tr><th>Severity</th><th>Confidence</th><th>Finding</th><th>Evidence</th><th>Impact</th><th>Remediation</th></tr></thead><tbody>';
		foreach ( $rows as $row ) {
			echo '<tr><td>' . esc_html( strtoupper( $row->severity ) ) . '</td><td>' . esc_html( strtoupper( $row->confidence ) ) . '</td><td>' . esc_html( $row->title ) . '</td><td><pre style="white-space:pre-wrap">' . esc_html( $row->evidence ) . '</pre></td><td>' . esc_html( $row->impact ) . '</td><td>' . esc_html( $row->remediation ) . '</td></tr>';
		}
		echo '</tbody></table>';
	}

	private function history_table( $rows ) {
		echo '<table class="widefat striped"><thead><tr><th>ID</th><th>Started</th><th>Finished</th><th>Status</th><th>Phase / error</th></tr></thead><tbody>';
		foreach ( $rows as $row ) { echo '<tr><td>' . absint( $row->id ) . '</td><td>' . esc_html( $row->started_at ) . '</td><td>' . esc_html( $row->finished_at ) . '</td><td>' . esc_html( $row->status ) . '</td><td>' . esc_html( $row->phase . ( $row->error_text ? ': ' . $row->error_text : '' ) ) . '</td></tr>'; }
		echo '</tbody></table>';
	}

	private function settings_page() {
		$hashes = (array) get_option( 'boreal_security_trusted_ip_hashes', array() );
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="boreal_security_settings">';
		wp_nonce_field( 'boreal_security_settings' );
		echo '<table class="form-table"><tr><th><label for="limit">Login failure limit</label></th><td><input id="limit" type="number" min="3" max="100" name="limit" value="' . absint( get_option( 'boreal_security_login_limit', 10 ) ) . '"></td></tr><tr><th><label for="trusted">Trusted recovery IPs</label></th><td><textarea id="trusted" name="trusted" rows="5" class="large-text"></textarea><p>Enter IPs to replace the saved trusted list. IPs are immediately HMAC-hashed and never stored in plaintext. Currently saved: ' . count( $hashes ) . '. Leave blank to retain it. BOREAL_SECURITY_TRUSTED_IPS in wp-config.php is also supported.</p></td></tr><tr><th>Vulnerability data</th><td>No provider configured. The extension point <code>boreal_security_vulnerability_findings</code> accepts site-owner-supplied provider results; no licensed feed is bundled or redistributed.</td></tr></table>';
		submit_button();
		echo '</form>';
	}

	public function settings() {
		check_admin_referer( 'boreal_security_settings' );
		if ( ! current_user_can( 'manage_options' ) ) { wp_die( esc_html__( 'Permission denied.', 'boreal-security' ) ); }
		update_option( 'boreal_security_login_limit', min( 100, max( 3, absint( $_POST['limit'] ?? 10 ) ) ) );
		$raw = isset( $_POST['trusted'] ) ? sanitize_textarea_field( wp_unslash( $_POST['trusted'] ) ) : '';
		if ( '' !== trim( $raw ) ) {
			$hashes = array();
			foreach ( preg_split( '/[\s,]+/', $raw ) as $ip ) { if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) { $hashes[] = hash_hmac( 'sha256', $ip, wp_salt( 'auth' ) ); } }
			update_option( 'boreal_security_trusted_ip_hashes', array_values( array_unique( $hashes ) ), false );
		}
		boreal_security_audit( 'settings_updated' );
		wp_safe_redirect( admin_url( 'admin.php?page=boreal-security-settings' ) ); exit;
	}

	private function script() {
		$config = wp_json_encode( array( 'url' => admin_url( 'admin-ajax.php' ), 'nonce' => wp_create_nonce( 'boreal_security_scan' ) ) );
		echo '<script>(function(){const c=' . $config . ',b=document.getElementById("boreal-scan"),s=document.getElementById("boreal-status");async function call(action,data){const p=new URLSearchParams(Object.assign({action,nonce:c.nonce},data||{}));const r=await fetch(c.url,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:p});const j=await r.json();if(!r.ok||!j.success)throw new Error(j.data&&j.data.message||"Scan request failed");return j.data}async function batch(id){const x=await call("boreal_security_batch",{scan_id:id});s.textContent="Scan phase: "+x.phase;if(x.done){s.textContent="Scan complete. Reloading…";location.reload()}else{setTimeout(()=>batch(id).catch(fail),100)}}function fail(e){b.disabled=false;s.textContent="Scan failed: "+e.message}b.onclick=async()=>{b.disabled=true;s.textContent="Starting…";try{const x=await call("boreal_security_start");batch(x.scan_id).catch(fail)}catch(e){fail(e)}}})();</script>';
	}

	public function export() {
		check_admin_referer( 'boreal_security_export' );
		if ( ! current_user_can( 'manage_options' ) ) { wp_die( esc_html__( 'Permission denied.', 'boreal-security' ) ); }
		global $wpdb;
		$rows = $wpdb->get_results( 'SELECT scan_id,check_id,severity,confidence,title,evidence,impact,remediation,status,created_at FROM ' . Boreal_Security_Database::table( 'findings' ) . ' ORDER BY id DESC', ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		$format = isset( $_GET['format'] ) ? sanitize_key( wp_unslash( $_GET['format'] ) ) : 'json';
		nocache_headers();
		header( 'Content-Disposition: attachment; filename=boreal-security-findings.' . ( 'csv' === $format ? 'csv' : 'json' ) );
		if ( 'csv' === $format ) {
			header( 'Content-Type: text/csv; charset=utf-8' );
			$out = fopen( 'php://output', 'w' );
			fputcsv( $out, array_keys( $rows[0] ?? array( 'scan_id' => '', 'check_id' => '', 'severity' => '', 'confidence' => '', 'title' => '', 'evidence' => '', 'impact' => '', 'remediation' => '', 'status' => '', 'created_at' => '' ) ) );
			foreach ( $rows as $row ) { fputcsv( $out, $row ); }
			fclose( $out );
		} else {
			header( 'Content-Type: application/json; charset=utf-8' );
			echo wp_json_encode( array( 'product' => 'Boreal Security', 'generated_at' => gmdate( 'c' ), 'findings' => $rows ), JSON_PRETTY_PRINT );
		}
		boreal_security_audit( 'findings_exported', array( 'format' => $format ) ); exit;
	}
}
