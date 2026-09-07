<?php
defined( 'ABSPATH' ) || exit;

class Boreal_Security_Login_Guard {
	public function init() {
		add_filter( 'authenticate', array( $this, 'throttle' ), 5, 3 );
		add_action( 'wp_login_failed', array( $this, 'failed' ) );
		add_action( 'wp_login', array( $this, 'success' ) );
	}

	private function ip() {
		$raw = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated
		return filter_var( $raw, FILTER_VALIDATE_IP ) ? $raw : 'unknown';
	}

	private function key() {
		return 'boreal_security_login_' . hash_hmac( 'sha256', $this->ip(), wp_salt( 'auth' ) );
	}

	private function trusted() {
		$trusted = (array) get_option( 'boreal_security_trusted_ip_hashes', array() );
		if ( defined( 'BOREAL_SECURITY_TRUSTED_IPS' ) ) {
			foreach ( preg_split( '/\s*,\s*/', BOREAL_SECURITY_TRUSTED_IPS ) as $ip ) {
				if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) { $trusted[] = hash_hmac( 'sha256', $ip, wp_salt( 'auth' ) ); }
			}
		}
		return in_array( hash_hmac( 'sha256', $this->ip(), wp_salt( 'auth' ) ), $trusted, true );
	}

	public function throttle( $user, $username, $password ) {
		if ( $this->trusted() ) { return $user; }
		$count = (int) get_transient( $this->key() );
		if ( $count >= max( 3, absint( get_option( 'boreal_security_login_limit', 10 ) ) ) ) {
			return new WP_Error( 'boreal_security_throttled', __( 'Too many failed login attempts. Wait 15 minutes or use a trusted recovery IP configured by an administrator.', 'boreal-security' ) );
		}
		return $user;
	}

	public function failed() {
		if ( $this->trusted() ) { return; }
		$key = $this->key();
		set_transient( $key, (int) get_transient( $key ) + 1, 15 * MINUTE_IN_SECONDS );
	}

	public function success() {
		delete_transient( $this->key() );
	}
}
