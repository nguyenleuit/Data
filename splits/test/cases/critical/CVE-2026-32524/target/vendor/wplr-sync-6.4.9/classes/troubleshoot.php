<?php

// Will display potential issues (used in the Photo Engine > Settings).

class Meow_WPLR_Sync_Troubleshoot {

	public function __construct() {
		//add_filter( 'wplr_issues', array( $this, 'w3_total_cache' ), 10, 1 ); // Seems like it's fine now
		//add_filter( 'wplr_issues', array( $this, 'permalink_structure' ), 10, 1 ); // No problem with the new API
		add_filter( 'wplr_issues', array( $this, 'wordfence' ), 10, 1 ); // No problem with the new API

		//NinjaFirewall
		add_filter( 'wplr_issues', array( $this, 'ninjafirewall' ), 10, 1 ); // No problem with the new API
	}

	function display() {
		$issues = apply_filters( 'wplr_issues', array() );
		if ( empty( $issues ) ) {
			_e( "Everything is fine.", 'wplr-sync' );
			return;
		}
		echo "<ul>";
		foreach ( $issues as $issue )
			echo '<li">' . $issue . '</li>';
		echo "</ul>";
	}

	public function issues() {
		return apply_filters( 'wplr_issues', array() );
	}

	public function ninjafirewall( $issues ) {
		if ( defined( 'NFW_ENGINE_VERSION' ) ) {
			$nfw_options = get_option( 'nfw_options' );
			if ( $nfw_options['uploads'] !== '1' )
				array_push( $issues, __( 'NinjaFirewall seems to prevent files from being uploaded. Check the Uploads option.', 'wplr-sync' ) );
		}
		return $issues;
	}

	public function wordfence( $issues ) {
		if ( class_exists( 'wordfence' ) ) {
			array_push( $issues, __( 'WordFence firewall usually prevents requests from Lightroom. Have a look a the section about how to handle this issue <a target="_blank" href="https://meowapps.com/wplr-sync-debug/">here</a>.', 'wplr-sync' ) );
		}
		return $issues;
	}

	// Permalink Structure
	public function permalink_structure( $issues ) {
		$permastruct = get_option( 'permalink_structure' );
		if ( empty( $permastruct ) ) {
			array_push( $issues, __( 'Photo Engine will not work properly if your permalinks are set up on "Plain". Please pick a dynamic structure for your permalinks (Settings > Permalinks).', 'wplr-sync' ) );
		}
		return $issues;
	}

	// W3 Total Cache
	public function w3_total_cache( $issues ) {

		if ( defined( 'W3TC' ) && function_exists( 'w3tc_config' ) ) {
			$config = w3tc_config();
			if ( !empty( $config ) && $config->get_string( 'dbcache.enabled' ) ) {
				array_push( $issues, __( 'Photo Engine will not work properly because you are using W3 Total Cache with the Database Cached enabled. For some reason, this option breaks the syncing process.', 'wplr-sync' ) );
			}
		}
		return $issues;
	}

}

?>