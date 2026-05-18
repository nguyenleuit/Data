<?php

class Meow_WPLR_Sync_Public_API {
	private $route_prefix = 'wplr/v1';

	public function __construct() {
		add_action( 'rest_api_init', array( $this, 'init_rest' ) );
	}

	function init_rest() {
		register_rest_route( 'wplr/v1', '/auth', array(
			'methods' => 'GET',
			'permission_callback' => '__return_true',
			'callback' => array( $this, 'auth' ),
			'args' => array(
				'in' => array()
			)
		) );
		register_rest_route( 'wplr/v1', '/hierarchy', array(
			'methods' => 'GET',
			'permission_callback' => '__return_true',
			'callback' => array( $this, 'hierarchy' ),
			'args' => array(
				'in' => array()
			)
		) );
		register_rest_route( 'wplr/v1', '/gallery/(?P<id>[0-9]+)', array(
			'methods' => 'GET',
			'permission_callback' => '__return_true',
			'callback' => array( $this, 'gallery' ),
			'args' => array(
				'id' => array()
			)
		) );
	}

	// Process arguments
	function preprocess( $args = null ) {
		$this->running = true;
		if ( !empty( $args ) ) {
			$args = json_decode( $args->get_body(), true );
			if ( $args && $args['all'] )
				return $args['all'];
		}
		return array();
	}

	function postprocess() {
		$this->running = false;
	}

	// Authenticate and share the useful arguments.
	function init_with( &$args ) {
		global $wplr;
		// Debug Auth
		if ( count( $args ) < 3 ) {
			$this->error = new Meow_WPLR_Sync_Error( 403, "Authentification is missing." );
			$wplr->log( "Authentification is missing." );
			return false;
		}
		$blog_id	= array_shift( $args );
		$username = array_shift( $args );
		$password = array_shift( $args );
		$user = wp_authenticate( $username, $password );
		if ( is_wp_error( $user ) ) {
			$this->error = Meow_WPLR_Sync_Error::createByContext( 'wp_authenticate', $user->get_error_code(), strip_tags($user->get_error_message()) );
			$this->error->getContext()
				->set( 'username', $username )
				->set( 'password', $password );
			$wplr->log( $this->error->getMessage() );
			return false;
		}
		else if ( empty( $user ) ) {
			$this->error = new Meow_WPLR_Sync_Error( 403, __( 'Incorrect username or password.' ) );
			$wplr->log( $this->error );
			return false;
		}
		wp_set_current_user( $user->ID );
		if ( !current_user_can( 'upload_files' ) ) {
			$this->error = Meow_WPLR_Sync_Error::createByContext( 'wp_check_user_caps', 'cannot_upload' );
			$wplr->log( $this->error );
			return false;
		}
		$user = get_userdata( $user->ID );
		$wplr->log( "Auth: " . $user->user_login );
		return $user;
	}

	// API for JSON Clients

	function get_auth_header() {
		$headers = null;
		if ( isset( $_SERVER['Authorization'] ) )
			$headers = trim( $_SERVER["Authorization"]);
		else if ( isset( $_SERVER['HTTP_AUTHORIZATION'] ) )
			$headers = trim( $_SERVER["HTTP_AUTHORIZATION"] );
		elseif ( function_exists( 'apache_request_headers' ) ) {
			$requestHeaders = apache_request_headers();
			$requestHeaders = array_combine( array_map( 'ucwords', array_keys( $requestHeaders ) ), array_values( $requestHeaders ) );
			if ( isset($requestHeaders['Authorization'] ) )
				$headers = trim($requestHeaders['Authorization'] );
		}
		return $headers;
	}

	function get_bearer_token() {
		$headers = $this->get_auth_header();
		if ( !empty( $headers ) )
			if ( preg_match( '/Bearer\s(\S+)/', $headers, $matches ) )
				return $matches[1];
		return null;
	}

	function check_token() {
		$wplr_token = get_transient( 'wplr_auth_token' );
		$token = isset( $_COOKIE["wplr_auth_token"] ) ? $_COOKIE["wplr_auth_token"] : null;
		if ( is_null( $token ) )
			$token = $this->get_bearer_token();
		if ( is_null( $token ) )
			$token = isset( $_GET["wplr_auth_token"] ) ? $_GET["wplr_auth_token"] : null;
		if ( !$token )
			return "Authentification is required to access Photo Engine API.";
		if ( $wplr_token === null )
			return "Authentification has expired. Use the new QR code in the Photo Engine admin.";
		if ( $token != $wplr_token )
			return "Authentification failed.";
		return true;
	}

	// Auth
	function auth( $args ) {
		global $wplr;
		$this->preprocess();
		$check = $this->check_token();
		if ( $check !== true ) {
			$this->postprocess();
			return new WP_Error( 'auth_failed', $check, array( 'status' => 401 ) );
		}
		$this->result = json_encode( array(
			'success' => true,
			'message' => "Authentification successful."
		) );
		$this->postprocess();
		return $this->result;
	}

	function hierarchy( $args ) {
		global $wplr;
		$check = $this->check_token();
		if ( $check !== true ) {
			$this->postprocess();
			return new WP_Error( 'auth_failed', $check, array( 'status' => 401 ) );
		}
		$this->preprocess();
		$this->result = $wplr->get_hierarchy();
		$this->postprocess();
		return $this->result;
	}

	function gallery( $args ) {
		global $wplr;
		$this->preprocess();
		$check = $this->check_token();
		if ( $check !== true ) {
			$this->postprocess();
			return new WP_Error( 'auth_failed', $check, array( 'status' => 401 ) );
		}
		$this->result = $wplr->get_gallery( $args['id'] );
		$this->postprocess();
		return $this->result;
	}

}

?>
