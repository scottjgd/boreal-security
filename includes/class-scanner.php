<?php
defined( 'ABSPATH' ) || exit;

class Boreal_Security_Scanner {
	const FILE_BATCH = 150;

	public function start() {
		global $wpdb;
		$inserted = $wpdb->insert(
			Boreal_Security_Database::table( 'scans' ),
			array( 'started_at' => current_time( 'mysql', true ), 'status' => 'running', 'phase' => 'posture', 'cursor' => '{}' ),
			array( '%s', '%s', '%s', '%s' )
		);
		if ( false === $inserted || ! $wpdb->insert_id ) {
			return new WP_Error( 'scan_start_failed', __( 'The scan could not be started because its database record could not be created. Check the WordPress database and try again.', 'boreal-security' ) );
		}
		$id = (int) $wpdb->insert_id;
		boreal_security_audit( 'scan_started', array( 'scan_id' => $id ) );
		return $id;
	}

	public function batch( $scan_id ) {
		global $wpdb;
		$scan = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . Boreal_Security_Database::table( 'scans' ) . ' WHERE id=%d', $scan_id ) ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		if ( ! $scan || 'running' !== $scan->status ) {
			return new WP_Error( 'invalid_scan', __( 'The scan is missing or is not running.', 'boreal-security' ) );
		}
		try {
			$next = $this->{'phase_' . $scan->phase}( $scan_id, json_decode( $scan->cursor, true ) ?: array() );
			if ( 'done' === $next['phase'] ) {
				$wpdb->update( Boreal_Security_Database::table( 'scans' ), array( 'status' => 'complete', 'phase' => 'done', 'finished_at' => current_time( 'mysql', true ), 'cursor' => '{}' ), array( 'id' => $scan_id ) );
				boreal_security_audit( 'scan_completed', array( 'scan_id' => $scan_id ) );
				do_action( 'boreal_security_scan_completed', $scan_id );
				return array( 'done' => true, 'phase' => 'done' );
			}
			$wpdb->update( Boreal_Security_Database::table( 'scans' ), array( 'phase' => $next['phase'], 'cursor' => wp_json_encode( $next['cursor'] ) ), array( 'id' => $scan_id ) );
			return array( 'done' => false, 'phase' => $next['phase'] );
		} catch ( Throwable $error ) {
			$wpdb->update( Boreal_Security_Database::table( 'scans' ), array( 'status' => 'failed', 'error_text' => $error->getMessage(), 'finished_at' => current_time( 'mysql', true ) ), array( 'id' => $scan_id ) );
			boreal_security_audit( 'scan_failed', array( 'scan_id' => $scan_id, 'error' => $error->getMessage() ) );
			return new WP_Error( 'scan_failed', $error->getMessage() );
		}
	}

	private function finding( $scan_id, $check, $severity, $title, $evidence, $remediation ) {
		global $wpdb;
		$confidence = in_array( $severity, array( 'critical', 'error' ), true ) ? 'high' : 'medium';
		$impact     = $this->impact_for_severity( $severity );
		$wpdb->insert( Boreal_Security_Database::table( 'findings' ), array(
			'scan_id' => $scan_id, 'check_id' => $check, 'severity' => $severity,
			'title' => $title, 'evidence' => wp_json_encode( $evidence, JSON_PRETTY_PRINT ),
			'confidence' => $confidence, 'impact' => $impact,
			'remediation' => $remediation, 'created_at' => current_time( 'mysql', true ),
		) );
	}

	private function impact_for_severity( $severity ) {
		$impacts = array(
			'critical' => __( 'A confirmed integrity or execution risk could permit site compromise.', 'boreal-security' ),
			'high'     => __( 'This condition materially increases the likelihood or effect of compromise.', 'boreal-security' ),
			'medium'   => __( 'This weakens security posture and should be reviewed during routine maintenance.', 'boreal-security' ),
			'error'    => __( 'The check could not finish, so this area must not be treated as verified clean.', 'boreal-security' ),
			'info'     => __( 'This is contextual evidence for review, not a confirmed security defect.', 'boreal-security' ),
		);
		return isset( $impacts[ $severity ] ) ? $impacts[ $severity ] : $impacts['medium'];
	}

	private function phase_posture( $id ) {
		global $wp_version;
		if ( version_compare( PHP_VERSION, '8.1', '<' ) ) {
			$this->finding( $id, 'php.version', 'medium', 'PHP is approaching or beyond end of support', array( 'version' => PHP_VERSION ), 'Upgrade PHP after testing backups and compatibility.' );
		}
		$updates = get_site_transient( 'update_core' );
		if ( isset( $updates->updates[0]->response ) && 'upgrade' === $updates->updates[0]->response ) {
			$this->finding( $id, 'wordpress.update', 'high', 'A WordPress core update is available', array( 'installed' => $wp_version, 'offered' => $updates->updates[0]->current ), 'Back up and update WordPress core.' );
		}
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			$this->finding( $id, 'config.debug', 'medium', 'WP_DEBUG is enabled', array( 'WP_DEBUG' => true ), 'Disable debug display on production systems.' );
		}
		if ( ! is_ssl() ) {
			$this->finding( $id, 'transport.https', 'high', 'WordPress is not using HTTPS', array( 'home_url' => home_url() ), 'Configure a valid TLS certificate and HTTPS URLs.' );
		}
		return array( 'phase' => 'core', 'cursor' => array() );
	}

	private function phase_core( $id ) {
		global $wp_version, $wp_local_package;
		require_once ABSPATH . 'wp-admin/includes/update.php';
		$locale = isset( $wp_local_package ) ? $wp_local_package : 'en_US';
		$checksums = get_core_checksums( $wp_version, $locale );
		if ( false === $checksums ) {
			$this->finding( $id, 'core.integrity', 'error', 'Core integrity could not be verified', array( 'source' => 'WordPress Core API', 'version' => $wp_version, 'locale' => $locale ), 'Retry the explicit scan when WordPress.org is reachable.' );
		} else {
			$changed = array();
			foreach ( $checksums as $file => $hash ) {
				$path = ABSPATH . $file;
				if ( ! is_file( $path ) || md5_file( $path ) !== $hash ) { // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_md5_file
					$changed[] = $file;
					if ( count( $changed ) >= 50 ) { break; }
				}
			}
			if ( $changed ) {
				$this->finding( $id, 'core.integrity', 'critical', 'WordPress core files differ from official checksums', array( 'source' => 'WordPress Core API', 'files' => $changed, 'truncated' => 50 === count( $changed ) ), 'Reinstall the matching WordPress version from a trusted source and investigate changes.' );
			}
		}
		return array( 'phase' => 'inventory', 'cursor' => array() );
	}

	private function phase_inventory( $id ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		require_once ABSPATH . 'wp-admin/includes/theme.php';
		$plugins = array();
		foreach ( get_plugins() as $file => $data ) { $plugins[] = array( 'file' => $file, 'name' => $data['Name'], 'version' => $data['Version'], 'integrity' => 'unverifiable: no trusted checksum source requested' ); }
		$themes = array();
		foreach ( wp_get_themes() as $slug => $theme ) { $themes[] = array( 'slug' => $slug, 'name' => $theme->get( 'Name' ), 'version' => $theme->get( 'Version' ), 'integrity' => 'unverifiable: no trusted checksum source requested' ); }
		$this->finding( $id, 'extensions.inventory', 'info', 'Plugin and theme integrity is unverifiable', array( 'plugins' => $plugins, 'themes' => $themes ), 'Review inventory and obtain packages from trusted publishers. This is not a clean-integrity result.' );
		return array( 'phase' => 'files', 'cursor' => array( 'offset' => 0 ) );
	}

	private function phase_files( $id, $cursor ) {
		$files = $this->files( ABSPATH, 5000 );
		$offset = absint( $cursor['offset'] ?? 0 );
		foreach ( array_slice( $files, $offset, self::FILE_BATCH ) as $path ) {
			$relative = ltrim( str_replace( wp_normalize_path( ABSPATH ), '', wp_normalize_path( $path ) ), '/' );
			$perms = fileperms( $path );
			if ( false !== $perms && ( $perms & 0002 ) ) {
				$this->finding( $id, 'file.permissions', 'high', 'World-writable file found', array( 'path' => $relative, 'mode' => substr( sprintf( '%o', $perms ), -4 ) ), 'Remove world-write permission after confirming the required owner.' );
			}
			if ( preg_match( '#^(?:\.env|composer\.(?:json|lock)|wp-config\.php\.|.*\.(?:sql|bak|old))#i', basename( $path ) ) ) {
				$this->finding( $id, 'file.exposure', 'high', 'Potentially exposed sensitive file', array( 'path' => $relative ), 'Move or remove the file and deny web access.' );
			}
		}
		$offset += self::FILE_BATCH;
		return $offset < count( $files ) ? array( 'phase' => 'files', 'cursor' => array( 'offset' => $offset ) ) : array( 'phase' => 'uploads', 'cursor' => array( 'offset' => 0 ) );
	}

	private function phase_uploads( $id, $cursor ) {
		$upload = wp_get_upload_dir();
		$files = empty( $upload['basedir'] ) ? array() : $this->files( $upload['basedir'], 3000 );
		$offset = absint( $cursor['offset'] ?? 0 );
		foreach ( array_slice( $files, $offset, self::FILE_BATCH ) as $path ) {
			$relative = ltrim( str_replace( wp_normalize_path( ABSPATH ), '', wp_normalize_path( $path ) ), '/' );
			if ( preg_match( '/\.(?:php\d*|phtml|phar)$/i', $path ) ) {
				$this->finding( $id, 'uploads.executable', 'critical', 'Executable file found in uploads', array( 'path' => $relative, 'sha256' => hash_file( 'sha256', $path ) ), 'Inspect and quarantine only after confirming it is not required.' );
			} elseif ( filesize( $path ) <= 1048576 ) {
				$sample = file_get_contents( $path, false, null, 0, 65536 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
				if ( is_string( $sample ) && preg_match( '/(?:eval\s*\(\s*base64_decode|gzinflate\s*\(\s*base64_decode|shell_exec\s*\()/i', $sample ) ) {
					$this->finding( $id, 'malware.heuristic', 'high', 'Suspicious code pattern found', array( 'path' => $relative, 'sha256' => hash_file( 'sha256', $path ), 'rule' => 'bounded-obfuscation-or-shell-pattern' ), 'Have a qualified responder inspect the file; heuristic matches can be false positives.' );
				}
			}
		}
		$offset += self::FILE_BATCH;
		return $offset < count( $files ) ? array( 'phase' => 'uploads', 'cursor' => array( 'offset' => $offset ) ) : array( 'phase' => 'database', 'cursor' => array() );
	}

	private function phase_database( $id ) {
		global $wpdb;
		$admins = get_users( array( 'role' => 'administrator', 'fields' => array( 'ID', 'user_login', 'user_registered' ) ) );
		if ( count( $admins ) > 5 ) {
			$this->finding( $id, 'admin.count', 'medium', 'Many administrator accounts exist', array( 'count' => count( $admins ), 'accounts' => $admins ), 'Remove unnecessary administrator access and require strong authentication.' );
		}
		$cron = _get_cron_array();
		$suspicious = array();
		foreach ( (array) $cron as $hooks ) {
			foreach ( array_keys( $hooks ) as $hook ) {
				if ( preg_match( '/(?:eval|base64|shell|cmd)/i', $hook ) ) { $suspicious[] = $hook; }
			}
		}
		$autoload = (int) $wpdb->get_var( "SELECT SUM(LENGTH(option_value)) FROM {$wpdb->options} WHERE autoload IN ('yes','on','auto-on','auto')" );
		if ( $suspicious || $autoload > 3000000 ) {
			$this->finding( $id, 'persistence.database', 'medium', 'Database persistence indicators require review', array( 'suspicious_cron_hooks' => array_values( array_unique( $suspicious ) ), 'autoload_bytes' => $autoload ), 'Review cron callbacks and large autoloaded options before removal.' );
		}
		$provider_findings = apply_filters( 'boreal_security_vulnerability_findings', array(), $id );
		foreach ( (array) $provider_findings as $item ) {
			if ( ! is_array( $item ) || empty( $item['title'] ) || empty( $item['evidence'] ) ) { continue; }
			$this->finding( $id, 'vulnerability.provider', sanitize_key( $item['severity'] ?? 'medium' ), sanitize_text_field( $item['title'] ), $item['evidence'], sanitize_text_field( $item['remediation'] ?? 'Review the provider evidence and update the affected component.' ) );
		}
		return array( 'phase' => 'done', 'cursor' => array() );
	}

	private function files( $root, $limit ) {
		$out = array();
		if ( ! is_dir( $root ) ) { return $out; }
		$iterator = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::LEAVES_ONLY );
		foreach ( $iterator as $file ) {
			if ( $file->isFile() && ! $file->isLink() ) { $out[] = $file->getPathname(); }
			if ( count( $out ) >= $limit ) { break; }
		}
		sort( $out, SORT_STRING );
		return $out;
	}
}
