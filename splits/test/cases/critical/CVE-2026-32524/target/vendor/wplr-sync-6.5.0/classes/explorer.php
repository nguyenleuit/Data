<?php

class Meow_WPLR_Sync_Explorer {

	public $screen;

	public function __construct() {

		$mode = get_option( 'wplr_library_show_hierarchy', 'none' );

		// FILTERS IN THE MEDIA LIBRARY
		//if ( $mode === 'filters' || $mode === 'explorer' ) {
			add_action( 'pre_get_posts', array( $this, 'media_filters' ) );
			add_action( 'restrict_manage_posts', array( $this, 'media_dropdown' ) );
		//}

		// UI WITH HIERARCHY IN THE MEDIA LIBRARY
		//if ( $mode === 'explorer' ) {
			 add_action( 'admin_head', array( $this, 'admin_head' ) );
			 add_action( 'admin_footer', array( $this, 'admin_footer' ) );
			// add_action( 'admin_enqueue_scripts', array( $this, 'admin_enqueue_scripts' ) );
		//}
	}

	/*
		FILTERS IN THE MEDIA LIBRARY
	*/

	function media_filters( $q ) {
		$col_id = isset( $_GET['col_id'] ) ? (int)$_GET['col_id'] : 0;
		if ( isset( $_POST['query'] ) && isset( $_POST['query']['col_id'] ) )
			$col_id = (int)( $_POST['query']['col_id'] );
		if ( $col_id < 1 ) {
			return;
		}
		global $wplr;
		$pids = $wplr->get_media_from_collection( $col_id );
		if ( !empty( $pids ) ) {
			$q->set( 'post__in', $pids );
			$q->set( 'orderby', 'post__in' );
		}
		else
			$q->set( 'p', -1 );
		return $q;
	}

	function media_dropdown() {
		if ( !$this->shouldBeOverriden() )
			return;
		$wp_parent_folder = null;
		global $wpdb, $wplr;
		$tbl_c = $wpdb->prefix . 'lrsync_collections';
		$collections = $wpdb->get_results( "SELECT * FROM $tbl_c WHERE wp_folder_id IS NULL ORDER BY lr_col_id", OBJECT );
		$col_id = isset( $_GET['col_id'] ) ? (int)$_GET['col_id'] : 0;
		echo '<a class="dashicons-before dashicons-camera" style="top: 5px; position: relative; margin: 2px;"></a>
			<select name="col_id" id="wplr_col_id_selector" class="postform">
			<option value="-1" selected="selected">All Media</option>';
		$collections = $wplr->read_collections_recursively();
		foreach ( $collections as $c ) {
			echo '<option class="level-' . $c['level'] . '"' .
				( $c['is_folder'] ? ' disabled' : '' ) . ' value="' .
				$c['wp_col_id'] . '" ' . selected( $c['wp_col_id'], $col_id ) . '>' .
				str_pad( "", $c['level'] * 6 * 3, "&nbsp;" ) . $c['name'] .
				'</option>';
		}
		echo '</select>';
	}

	/*
		UI WITH HIERARCHY IN THE MEDIA LIBRARY
	*/

	function admin_head() {
		if ( !$this->shouldBeOverriden() )
			return;
		ob_start( array( $this, "hide_media_gallery" ) );
	}

	function hide_media_gallery( $buffer ) {
		if ( !isset( $buffer ) || trim( $buffer ) === '' )
			return $buffer;
		$buffer = str_replace( 'id="posts-filter"', 'id="posts-filter" style="display: none;"', $buffer );
		return $buffer;
	}

	function admin_footer() {
		if ( !$this->shouldBeOverriden() )
			return;
		@ob_end_flush();
	}

	function shouldBeOverriden() {
		$should = false;
		$screen = get_current_screen();

		if ($screen->base === 'upload') return true;

		if ( isset( $_SERVER['QUERY_STRING'] ) ) {
			if ( preg_match( '/action=edit/', $_SERVER['QUERY_STRING'] ) )
				return true;
		}
	}

}

?>
