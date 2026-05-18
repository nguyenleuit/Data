<?php

class Meow_WPLR_Sync_UI {
	private $core = null;

	function __construct( $core ) {
		$this->core = $core;
		add_action( 'admin_menu', array( $this, 'admin_menu' ) );
	}

	function admin_menu() {
		if (get_option( 'wplr_media_organizer' )) {
			add_media_page( 'Organizer', __( 'Organizer', 'wplr-sync' ), 'read', 
				'wplr_sync_dashboard', array( $this, 'wplr_sync_dashboard' ), 1 );
		}
	}

	public function wplr_sync_dashboard() {
		echo '<div id="wplr-sync-dashboard"></div>';
	}
}
