<?php
defined( 'ABSPATH' ) || exit;

class Boreal_Security_Admin {
	public function init() {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'assets' ) );
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

	public function assets() {
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : '';
		if ( 0 === strpos( $page, 'boreal-security' ) ) {
			wp_enqueue_style( 'boreal-security-admin', BOREAL_SECURITY_URL . 'assets/admin.css', array(), BOREAL_SECURITY_VERSION );
		}
	}

	private function authorize_ajax() {
		check_ajax_referer( 'boreal_security_scan', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'boreal-security' ) ), 403 );
		}
	}

	public function ajax_start() {
		$this->authorize_ajax();
		$scan_id = ( new Boreal_Security_Scanner() )->start();
		if ( is_wp_error( $scan_id ) ) {
			wp_send_json_error( array( 'message' => $scan_id->get_error_message() ), 500 );
		}
		wp_send_json_success( array( 'scan_id' => $scan_id ) );
	}

	public function ajax_batch() {
		$this->authorize_ajax();
		$id     = isset( $_POST['scan_id'] ) ? absint( $_POST['scan_id'] ) : 0;
		$result = ( new Boreal_Security_Scanner() )->batch( $id );
		if ( is_wp_error( $result ) ) {
			wp_send_json_error( array( 'message' => $result->get_error_message() ), 500 );
		}
		wp_send_json_success( $result );
	}

	public function page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		global $wpdb;
		$page     = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : 'boreal-security';
		$scans    = $wpdb->get_results( 'SELECT * FROM ' . Boreal_Security_Database::table( 'scans' ) . ' ORDER BY id DESC LIMIT 50' ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		$findings = $wpdb->get_results( 'SELECT * FROM ' . Boreal_Security_Database::table( 'findings' ) . ' ORDER BY id DESC LIMIT 200' ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		$audit    = $wpdb->get_results( 'SELECT * FROM ' . Boreal_Security_Database::table( 'audit' ) . ' ORDER BY id DESC LIMIT 200' ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared

		echo '<div class="wrap boreal-security-admin">';
		$this->screen_header( $page );
		if ( 'boreal-security-settings' === $page ) {
			$this->settings_page();
		} elseif ( 'boreal-security-findings' === $page ) {
			$this->findings_table( $findings, true );
		} elseif ( 'boreal-security-history' === $page ) {
			$this->history_table( $scans );
		} elseif ( 'boreal-security-audit' === $page ) {
			$this->audit_table( $audit );
		} else {
			$this->dashboard( $scans, $findings );
			$this->script();
		}
		echo '</div>';
	}

	private function screen_header( $page ) {
		$section = 'boreal-security' === $page ? 'Overview' : str_replace( 'Boreal Security ', '', ucwords( str_replace( '-', ' ', str_replace( 'boreal-security-', '', $page ) ) ) );
		echo '<div class="boreal-screen-header"><div><p class="boreal-eyebrow">BOREALFORM / SECURITY OPERATIONS</p><h1><span class="boreal-brand-mark" aria-hidden="true">✦</span> Boreal Security <span class="boreal-edition-pill">FREE EDITION</span></h1><p class="boreal-screen-description">' . esc_html( $this->description( $page ) ) . '</p></div><div class="boreal-screen-context"><span class="boreal-context-dot"></span><span>' . esc_html( $section ) . '</span><span class="boreal-context-divider">/</span><span>Local evidence</span></div></div>';
	}

	private function description( $page ) {
		$descriptions = array(
			'boreal-security'          => __( 'A clear, evidence-first view of your WordPress security posture.', 'boreal-security' ),
			'boreal-security-findings' => __( 'Review the evidence behind every signal, with context and next steps.', 'boreal-security' ),
			'boreal-security-history'  => __( 'A durable record of scans run on this site.', 'boreal-security' ),
			'boreal-security-audit'    => __( 'A tamper-evident trail of important security actions.', 'boreal-security' ),
			'boreal-security-settings' => __( 'Tune the local controls that protect administrator access.', 'boreal-security' ),
		);
		return isset( $descriptions[ $page ] ) ? $descriptions[ $page ] : $descriptions['boreal-security'];
	}

	private function dashboard( $scans, $findings ) {
		$latest          = ! empty( $scans ) ? $scans[0] : null;
		$latest_findings = $latest ? array_values( array_filter( $findings, function ( $finding ) use ( $latest ) {
			return (int) $finding->scan_id === (int) $latest->id;
		} ) ) : array();
		$score           = $latest && 'complete' === $latest->status ? $this->score( $latest_findings ) : null;
		$counts          = $this->severity_counts( $latest_findings );

		echo '<div class="boreal-hero"><div class="boreal-hero-copy"><p class="boreal-eyebrow boreal-eyebrow-light">SITE SIGNAL / ' . esc_html( strtoupper( get_bloginfo( 'name' ) ) ) . '</p><h2>Your security picture,<br><em>without the noise.</em></h2><p>Run a bounded local scan and keep the evidence close to your site. Boreal Security shows what it knows, what it found, and what to do next.</p><div class="boreal-hero-actions"><button id="boreal-scan" class="button boreal-primary-button"><span class="boreal-button-icon">↗</span> ' . esc_html__( 'Run manual scan', 'boreal-security' ) . '</button><span id="boreal-status" class="boreal-scan-status" aria-live="polite"></span></div></div><div class="boreal-score-orbit"><div class="boreal-score-ring ' . ( null === $score ? 'is-empty' : '' ) . '"><div class="boreal-score-value">' . esc_html( null === $score ? '—' : $score ) . '</div><div class="boreal-score-label">' . esc_html__( 'evidence score', 'boreal-security' ) . '</div></div><span class="boreal-orbit-dot boreal-orbit-dot-one"></span><span class="boreal-orbit-dot boreal-orbit-dot-two"></span></div></div>';
		echo '<div class="boreal-stat-grid"><div class="boreal-stat-card"><span class="boreal-stat-kicker">LATEST SIGNAL</span><strong>' . esc_html( $latest ? strtoupper( $latest->status ) : 'NOT RUN' ) . '</strong><span>' . esc_html( $latest ? $this->date_label( $latest->finished_at ?: $latest->started_at ) : 'Start your first scan' ) . '</span></div><div class="boreal-stat-card"><span class="boreal-stat-kicker">OPEN FINDINGS</span><strong>' . esc_html( count( $latest_findings ) ) . '</strong><span>' . esc_html( $this->finding_summary( $counts ) ) . '</span></div><div class="boreal-stat-card"><span class="boreal-stat-kicker">SCAN MODE</span><strong>LOCAL / BOUNDED</strong><span>Resumable evidence collection</span></div><div class="boreal-stat-card boreal-stat-card-accent"><span class="boreal-stat-kicker">NEXT BEST ACTION</span><strong>' . esc_html( $latest ? 'Review findings' : 'Run a scan' ) . '</strong><span>Keep your evidence current</span></div></div>';
		echo '<div class="boreal-dashboard-columns"><section class="boreal-panel boreal-panel-findings"><div class="boreal-panel-heading"><div><p class="boreal-eyebrow">LATEST EVIDENCE</p><h2>What needs your attention</h2></div><a class="boreal-text-link" href="' . esc_url( admin_url( 'admin.php?page=boreal-security-findings' ) ) . '">View all findings <span>→</span></a></div>';
		if ( empty( $latest_findings ) ) {
			echo '<div class="boreal-empty-state"><span class="boreal-empty-icon">✓</span><div><h3>' . esc_html( $latest ? 'No findings in this scan' : 'Your first scan is waiting' ) . '</h3><p>' . esc_html( $latest ? 'Boreal Security did not record a finding in the latest completed scan.' : 'Start a manual scan to build your first evidence snapshot.' ) . '</p></div></div>';
		} else {
			$this->finding_list( array_slice( $latest_findings, 0, 5 ) );
		}
		echo '</section><aside class="boreal-panel boreal-panel-pro"><span class="boreal-pro-orb">✦</span><p class="boreal-eyebrow">BOREAL SECURITY PRO</p><h2>Make security<br>continuous.</h2><p>Keep a baseline, watch file changes, and get alerts before a quiet signal becomes a serious problem.</p><ul><li>Scheduled scans</li><li>File-change baselines</li><li>Alert-ready reports</li></ul><a class="boreal-secondary-button" href="' . esc_url( admin_url( 'admin.php?page=boreal-security-pro' ) ) . '">Explore Pro <span>↗</span></a></aside></div>';
		echo '<div class="boreal-principles"><span><b>01</b> Evidence first</span><span><b>02</b> Local by default</span><span><b>03</b> Portable by design</span><span class="boreal-principles-note">A signal is not a guarantee. It is a place to begin.</span></div>';
	}

	private function score( $findings ) {
		$deductions = array( 'critical' => 25, 'high' => 15, 'medium' => 7, 'error' => 5, 'info' => 0 );
		$score      = 100;
		foreach ( $findings as $finding ) {
			$score -= isset( $deductions[ $finding->severity ] ) ? $deductions[ $finding->severity ] : 5;
		}
		return max( 0, $score );
	}

	private function severity_counts( $findings ) {
		$counts = array( 'critical' => 0, 'high' => 0, 'medium' => 0, 'info' => 0 );
		foreach ( $findings as $finding ) {
			$key = isset( $counts[ $finding->severity ] ) ? $finding->severity : 'medium';
			$counts[ $key ]++;
		}
		return $counts;
	}

	private function finding_summary( $counts ) {
		if ( $counts['critical'] || $counts['high'] ) {
			return sprintf( '%d high-priority signal(s)', $counts['critical'] + $counts['high'] );
		}
		if ( $counts['medium'] ) {
			return sprintf( '%d medium-priority signal(s)', $counts['medium'] );
		}
		return 'No unresolved signals recorded';
	}

	private function finding_list( $rows ) {
		echo '<div class="boreal-finding-list">';
		foreach ( $rows as $row ) {
			echo '<article class="boreal-finding-item"><span class="boreal-severity-dot severity-' . esc_attr( $row->severity ) . '"></span><div class="boreal-finding-content"><div class="boreal-finding-meta"><span class="boreal-severity-label severity-text-' . esc_attr( $row->severity ) . '">' . esc_html( strtoupper( $row->severity ) ) . '</span><span>' . esc_html( strtoupper( $row->confidence ) ) . ' CONFIDENCE</span></div><h3>' . esc_html( $row->title ) . '</h3><p>' . esc_html( $row->impact ) . '</p></div><span class="boreal-finding-arrow">→</span></article>';
		}
		echo '</div>';
	}

	private function findings_table( $rows, $full = false ) {
		$base = wp_nonce_url( admin_url( 'admin-post.php?action=boreal_security_export&format=' ), 'boreal_security_export' );
		echo '<section class="boreal-panel boreal-table-panel"><div class="boreal-panel-heading"><div><p class="boreal-eyebrow">EVIDENCE LEDGER</p><h2>' . esc_html( $full ? 'All findings' : 'Latest findings' ) . '</h2><p class="boreal-panel-subtitle">Every record includes evidence, impact, and a suggested next step.</p></div><div class="boreal-export-actions"><a class="boreal-quiet-button" href="' . esc_url( $base . 'json' ) . '">Export JSON</a><a class="boreal-quiet-button" href="' . esc_url( $base . 'csv' ) . '">Export CSV</a></div></div>';
		if ( empty( $rows ) ) {
			echo '<div class="boreal-empty-state"><span class="boreal-empty-icon">✓</span><div><h3>No findings recorded</h3><p>Run a manual scan to populate the evidence ledger.</p></div></div></section>';
			return;
		}
		echo '<div class="boreal-table-scroll"><table class="widefat boreal-data-table"><thead><tr><th>Signal</th><th>Confidence</th><th>Finding</th><th>Evidence</th><th>Impact / next step</th></tr></thead><tbody>';
		foreach ( $rows as $row ) {
			echo '<tr><td><span class="boreal-severity-pill severity-pill-' . esc_attr( $row->severity ) . '">' . esc_html( strtoupper( $row->severity ) ) . '</span></td><td><span class="boreal-confidence">' . esc_html( strtoupper( $row->confidence ) ) . '</span></td><td><strong>' . esc_html( $row->title ) . '</strong></td><td><pre>' . esc_html( $row->evidence ) . '</pre></td><td><p>' . esc_html( $row->impact ) . '</p><p class="boreal-remediation">' . esc_html( $row->remediation ) . '</p></td></tr>';
		}
		echo '</tbody></table></div></section>';
	}

	private function history_table( $rows ) {
		echo '<section class="boreal-panel boreal-table-panel"><div class="boreal-panel-heading"><div><p class="boreal-eyebrow">SCAN HISTORY</p><h2>A record you can trust</h2><p class="boreal-panel-subtitle">Manual scans are bounded, resumable, and retained as evidence.</p></div></div><div class="boreal-table-scroll"><table class="widefat boreal-data-table"><thead><tr><th>Run</th><th>Started</th><th>Finished</th><th>Status</th><th>Phase / error</th></tr></thead><tbody>';
		if ( empty( $rows ) ) {
			echo '<tr><td colspan="5"><div class="boreal-table-empty">No scans have been run yet.</div></td></tr>';
		} else {
			foreach ( $rows as $row ) {
				echo '<tr><td><span class="boreal-run-id">#' . absint( $row->id ) . '</span></td><td>' . esc_html( $this->date_label( $row->started_at ) ) . '</td><td>' . esc_html( $row->finished_at ? $this->date_label( $row->finished_at ) : '—' ) . '</td><td><span class="boreal-status-pill status-' . esc_attr( $row->status ) . '">' . esc_html( strtoupper( $row->status ) ) . '</span></td><td>' . esc_html( $row->phase . ( $row->error_text ? ': ' . $row->error_text : '' ) ) . '</td></tr>';
			}
		}
		echo '</tbody></table></div></section>';
	}

	private function audit_table( $rows ) {
		echo '<section class="boreal-panel boreal-table-panel"><div class="boreal-panel-heading"><div><p class="boreal-eyebrow">AUDIT TRAIL</p><h2>Actions, recorded</h2><p class="boreal-panel-subtitle">A local history of security-relevant activity.</p></div></div><div class="boreal-table-scroll"><table class="widefat boreal-data-table"><thead><tr><th>Time (UTC)</th><th>User</th><th>Action</th><th>Details</th></tr></thead><tbody>';
		if ( empty( $rows ) ) {
			echo '<tr><td colspan="4"><div class="boreal-table-empty">No audit activity has been recorded yet.</div></td></tr>';
		} else {
			foreach ( $rows as $row ) {
				echo '<tr><td>' . esc_html( $this->date_label( $row->created_at ) ) . '</td><td>' . absint( $row->user_id ) . '</td><td><span class="boreal-action-label">' . esc_html( $row->action ) . '</span></td><td><pre>' . esc_html( $row->details ) . '</pre></td></tr>';
			}
		}
		echo '</tbody></table></div></section>';
	}

	private function settings_page() {
		$hashes = (array) get_option( 'boreal_security_trusted_ip_hashes', array() );
		echo '<section class="boreal-panel boreal-settings-panel"><div class="boreal-panel-heading"><div><p class="boreal-eyebrow">LOCAL CONTROLS</p><h2>Settings that stay on this site</h2><p class="boreal-panel-subtitle">Tune login protection and trusted recovery access without sending your secrets elsewhere.</p></div></div><form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="boreal-settings-form"><input type="hidden" name="action" value="boreal_security_settings">';
		wp_nonce_field( 'boreal_security_settings' );
		echo '<div class="boreal-form-row"><div><label for="limit">Login failure limit</label><p>Throttle repeated failed attempts from the same source.</p></div><input id="limit" type="number" min="3" max="100" name="limit" value="' . absint( get_option( 'boreal_security_login_limit', 10 ) ) . '"></div><div class="boreal-form-row boreal-form-row-wide"><div><label for="trusted">Trusted recovery IPs</label><p>One IP per line. Values are HMAC-hashed immediately and never stored in plaintext. ' . esc_html( count( $hashes ) ) . ' trusted address(es) saved.</p></div><textarea id="trusted" name="trusted" rows="5" placeholder="Leave blank to retain the current list"></textarea></div><div class="boreal-form-row boreal-form-row-wide"><div><label>Vulnerability data</label><p>No provider is configured. Site-owner-supplied results can be added through the <code>boreal_security_vulnerability_findings</code> extension point.</p></div><span class="boreal-disabled-chip">LOCAL ONLY</span></div><div class="boreal-form-actions">';
		submit_button( __( 'Save settings', 'boreal-security' ), 'primary boreal-primary-button', 'submit', false );
		echo '</div></form></section>';
	}

	private function date_label( $date ) {
		return $date ? get_date_from_gmt( $date, get_option( 'date_format' ) . ' ' . get_option( 'time_format' ) ) : '—';
	}

	private function script() {
		$config = wp_json_encode( array( 'url' => admin_url( 'admin-ajax.php' ), 'nonce' => wp_create_nonce( 'boreal_security_scan' ) ) );
		echo '<script>(function(){const c=' . $config . ',b=document.getElementById("boreal-scan"),s=document.getElementById("boreal-status");if(!b||!s)return;async function call(action,data){const p=new URLSearchParams(Object.assign({action,nonce:c.nonce},data||{}));const r=await fetch(c.url,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:p});const j=await r.json();if(!r.ok||!j.success)throw new Error(j.data&&j.data.message||"Scan request failed");return j.data}async function batch(id){const x=await call("boreal_security_batch",{scan_id:id});s.textContent="Scanning "+x.phase+"…";if(x.done){s.textContent="Scan complete. Refreshing evidence…";location.reload()}else{setTimeout(()=>batch(id).catch(fail),180)}}function fail(e){b.disabled=false;s.textContent="Scan failed: "+e.message;b.classList.remove("is-loading")}b.onclick=async()=>{b.disabled=true;b.classList.add("is-loading");s.textContent="Preparing local scan…";try{const x=await call("boreal_security_start");batch(x.scan_id).catch(fail)}catch(e){fail(e)}}})();</script>';
	}

	public function settings() {
		check_admin_referer( 'boreal_security_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Permission denied.', 'boreal-security' ) );
		}
		update_option( 'boreal_security_login_limit', min( 100, max( 3, absint( $_POST['limit'] ?? 10 ) ) ) );
		$raw = isset( $_POST['trusted'] ) ? sanitize_textarea_field( wp_unslash( $_POST['trusted'] ) ) : '';
		if ( '' !== trim( $raw ) ) {
			$hashes = array();
			foreach ( preg_split( '/[\s,]+/', $raw ) as $ip ) {
				if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					$hashes[] = hash_hmac( 'sha256', $ip, wp_salt( 'auth' ) );
				}
			}
			update_option( 'boreal_security_trusted_ip_hashes', array_values( array_unique( $hashes ) ), false );
		}
		boreal_security_audit( 'settings_updated' );
		wp_safe_redirect( admin_url( 'admin.php?page=boreal-security-settings' ) );
		exit;
	}

	public function export() {
		check_admin_referer( 'boreal_security_export' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Permission denied.', 'boreal-security' ) );
		}
		global $wpdb;
		$rows = $wpdb->get_results( 'SELECT scan_id,check_id,severity,confidence,title,evidence,impact,remediation,status,created_at FROM ' . Boreal_Security_Database::table( 'findings' ) . ' ORDER BY id DESC', ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		$format = isset( $_GET['format'] ) ? sanitize_key( wp_unslash( $_GET['format'] ) ) : 'json';
		nocache_headers();
		header( 'Content-Disposition: attachment; filename=boreal-security-findings.' . ( 'csv' === $format ? 'csv' : 'json' ) );
		if ( 'csv' === $format ) {
			header( 'Content-Type: text/csv; charset=utf-8' );
			$out = fopen( 'php://output', 'w' );
			fputcsv( $out, array_keys( $rows[0] ?? array( 'scan_id' => '', 'check_id' => '', 'severity' => '', 'confidence' => '', 'title' => '', 'evidence' => '', 'impact' => '', 'remediation' => '', 'status' => '', 'created_at' => '' ) ) );
			foreach ( $rows as $row ) {
				fputcsv( $out, $row );
			}
			fclose( $out );
		} else {
			header( 'Content-Type: application/json; charset=utf-8' );
			echo wp_json_encode( array( 'product' => 'Boreal Security', 'generated_at' => gmdate( 'c' ), 'findings' => $rows ), JSON_PRETTY_PRINT );
		}
		boreal_security_audit( 'findings_exported', array( 'format' => $format ) );
		exit;
	}
}