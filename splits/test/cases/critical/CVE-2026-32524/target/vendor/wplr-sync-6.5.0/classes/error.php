<?php
// Need 'class-IXR' for the 'IXR_Error' cass
require_once ABSPATH . WPINC . '/class-IXR.php';

/**
 * Error Object
 * TODO I want a generic response object class, not limited to errors.
 */
class Meow_WPLR_Sync_Error extends IXR_Error {

	/**
	 * Variables to be encoded to JSON.
	 * Must be public.
	 * Note: JsonSerializable is not available for PHP 5.3
	 */
	public
		$context = null,
		$reason = '';

	/**
	 * Instantiates with a specific context
	 * @param string|Meow_WPLR_Sync_Error_Context $context
	 * @param string $reason
	 * @param string $msg Alternative message
	 * @return Meow_WPLR_Sync_Error New instance
	 */
	public static function createByContext( $context, $reason = '', $msg = '' ) {
		$code = 400; // Generic client-side error (Bad Request)
		$msg = $msg ?: __( 'Unknown Error', 'wplr-sync' );

		$context = $context instanceof Meow_WPLR_Sync_Error_Context ?
			$context : new Meow_WPLR_Sync_Error_Context( $context );

		switch ( $context->getName() ) {
		case 'wp_authenticate': // Attempted to login WordPress
			$code = 401; // Unauthorized
			switch ( $reason ) {
			case 'empty_username': // Empty username supplied
				$msg = __( 'Please input your WP username', 'wplr-sync' );
				break;
			case 'empty_password': // Empty password supplied
				$msg = __( 'Please input your WP password', 'wplr-sync' );
				break;
			case 'invalid_username': // Specified user doesn't exist
				$msg = __( 'Invalid Username', 'wplr-sync' );
				break;
			case 'incorrect_password': // Password is incorrect
				$msg = __( 'Incorrect Password', 'wplr-sync' );
				break;
			}
			break;
		case 'wp_check_user_caps': // Checking user capability
			$code = 403; // Forbidden
			switch ( $reason ) {
			case 'cannot_upload': // User doesn't have permission to upload
				$msg = __( 'You do not have permission to upload files.' );
				break;
			}
			break;
		}
		$r = new static( $code, $msg );
		return $r
			->setReason( $reason )
			->setContext( $context );
	}

	public function __toString() {
		return $this->message;
	}

	public function getCode() {
		return $this->code;
	}

	/**
	 * @return string
	 */
	public function getMessage() {
		return $this->message;
	}

	/**
	 * @return Meow_WPLR_Sync_Error_Context
	 */
	public function getContext() {
		return $this->context;
	}

	/**
	 * @return string
	 */
	public function getReason() {
		return $this->reason;
	}

	/**
	 * @param Meow_WPLR_Sync_Error_Context $X
	 * @return Meow_WPLR_Sync_Error This
	 */
	public function setContext( $X ) {
		$this->context = $X;
		return $this;
	}

	/**
	 * @param string $X
	 * @return Meow_WPLR_Sync_Error This
	 */
	public function setReason( $X ) {
		$this->reason = $X;
		return $this;
	}

	/**
	 * @return array
	 */
	public function toArray() {
		return array (
			'code'    => $this->code,
			'message' => $this->message,
			'reason'  => $this->reason,
			'context' => $this->context->toArray()
		);
	}
}

/**
 * Error Context
 */
class Meow_WPLR_Sync_Error_Context {
	private
		$name,
		$data;

	/**
	 * @param string $name
	 */
	public function __construct( $name ) {
		$this->name = $name;
		$this->data = array ();
	}

	/**
	 * Returns the name of the context
	 * @return string
	 */
	public function getName() {
		return $this->name;
	}

	/**
	 * Returns the data associated with the specified key
	 * @param string $key
	 * @return mixed
	 */
	public function get( $key ) {
		return $this->data[$key];
	}

	/**
	 * Sets a data
	 * @param string $key
	 * @param mixed $value
	 * @return Meow_WPLR_Sync_Error_Context This
	 */
	public function set( $key, $value ) {
		$this->data[$key] = $value;
		return $this;
	}

	/**
	 * @return array
	 */
	public function toArray() {
		return array (
			'name' => $this->name,
			'data' => $this->data
		);
	}
}
