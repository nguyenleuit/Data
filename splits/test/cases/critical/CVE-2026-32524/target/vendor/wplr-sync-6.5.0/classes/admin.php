<?php
class Meow_WPLR_Sync_Admin extends MeowKit_WPLR_Admin {
	protected $wplr;

	public static $logo = 'data:image/svg+xml;base64,PHN2ZyB2ZXJzaW9uPSIxIiB2aWV3Qm94PSIwIDAgMTY1IDE2NSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KICA8c3R5bGU+CiAgICAuc3Qye2ZpbGw6IzgwNDYyNX0uc3Qze2ZpbGw6I2ZkYTk2MH0KICA8L3N0eWxlPgogIDxwYXRoIGQ9Ik03MiA3YTc2IDc2IDAgMCAxIDg0IDkxQTc1IDc1IDAgMSAxIDcyIDd6IiBmaWxsPSIjNGE2YjhjIi8+CiAgPHBhdGggZD0iTTQ4IDQ4YzIgNSAyIDEwIDUgMTQgNSA4IDEzIDE3IDIyIDIwbDEtMTBjMS0yIDMtMyA1LTNoMTNjMiAwIDQgMSA1IDNsMyA5IDQtMTBjMi0zIDYtMiA5LTJoMTFjMyAyIDMgNSAzIDhsMiAzN2MwIDMtMSA3LTQgOGgtMTJjLTIgMC0zLTItNS00LTEgMS0yIDMtNCAzLTUgMS05IDEtMTMtMS0zIDItNSAyLTkgMnMtOSAxLTEwLTNjLTItNC0xLTggMC0xMi04LTMtMTUtNy0yMi0xMi03LTctMTUtMTQtMjAtMjMtMy00LTUtOC01LTEzIDEtNCAzLTEwIDYtMTMgNC0zIDEyLTIgMTUgMnoiIGZpbGw9IiMxMDEwMTAiLz4KICA8cGF0aCBjbGFzcz0ic3QyIiBkPSJNNDMgNTFsNCAxMS02IDVoLTZjLTMtNS0zLTExIDAtMTYgMi0yIDYtMyA4IDB6Ii8+CiAgPHBhdGggY2xhc3M9InN0MyIgZD0iTTQ3IDYybDMgNmMwIDMgMCA0LTIgNnMtNCAyLTcgMmwtNi05aDZsNi01eiIvPgogIDxwYXRoIGNsYXNzPSJzdDIiIGQ9Ik01MCA2OGw4IDljLTMgMy01IDYtOSA4bC04LTljMyAwIDUgMCA3LTJzMy0zIDItNnoiLz4KICA8cGF0aCBkPSJNODIgNzRoMTJsNSAxOCAzIDExIDgtMjloMTNsMiA0MmgtOGwtMS0yLTEtMzEtMTAgMzItNyAxLTktMzMtMSAyOS0xIDRoLThsMy00MnoiIGZpbGw9IiNmZmYiLz4KICA8cGF0aCBjbGFzcz0ic3QzIiBkPSJNNTggNzdsNSA1Yy0xIDQtMiA4LTcgOGwtNy01YzQtMiA2LTUgOS04eiIvPgogIDxwYXRoIGNsYXNzPSJzdDIiIGQ9Ik02MyA4Mmw5IDUtNiA5LTEwLTZjNSAwIDYtNCA3LTh6Ii8+CiAgPHBhdGggY2xhc3M9InN0MyIgZD0iTTcyIDg3bDMgMS0xIDExLTgtMyA2LTEweiIvPgo8L3N2Zz4K';

	public function __construct() {
		parent::__construct( WPLR_SYNC_PREFIX, WPLR_SYNC_ENTRY, WPLR_SYNC_DOMAIN );
		if ( is_admin() ) {
			global $wplr;
			$this->wplr = $wplr;

			if ( current_user_can( 'upload_files' ) ) {
				add_action( 'show_user_profile', array ( $this, 'auth_token_field' ) );
				add_action( 'edit_user_profile', array ( $this, 'auth_token_field' ) );
				add_action( 'admin_menu', array( $this, 'admin_menu' ) );
			}

			add_filter( 'wplr_meowapps_is_registered', array( $this, '' ) );
			add_filter( 'media_row_actions', array( $this, 'media_row_actions' ), 10, 2 );
			add_action( 'wp_ajax_wplrsync_generate_auth_token', array ( $this, 'ajax_generate_auth_token' ) );
			add_action( 'wp_ajax_wplrsync_link', array( $wplr, 'wplrsync_link' ) );
			add_action( 'wp_ajax_wplrsync_unlink', array( $wplr, 'wplrsync_unlink' ) );
			add_action( 'wp_ajax_wplrsync_clean', array( $this, 'wplrsync_clean' ) );
			add_action( 'wp_ajax_wplrsync_extensions_reset', array( $this, 'wplrsync_extensions_reset' ) );
			add_action( 'wp_ajax_wplrsync_extensions_init', array( $this, 'wplrsync_extensions_init' ) );
			add_action( 'wp_ajax_wplrsync_extensions_query', array( $this, 'wplrsync_extensions_query' ) );
			add_action( 'add_meta_boxes', array( $this, 'add_format_warning_metabox' ) );
			//if ( get_option( 'wplr_library_show_hierarchy', 'none' ) !== 'none' ) {
				$wplr_medialib = new Meow_WPLR_Sync_Explorer();
			//}
			// Load the scripts only if they are needed by the current screen
			$uri = $_SERVER['REQUEST_URI'];
			$page = isset( $_GET["page"] ) ? $_GET["page"] : null;
			$is_media_library = preg_match( '/wp\-admin\/upload\.php/', $uri );
			$is_wplr_sync_screen = in_array( $page, [ 'wplr_sync_settings', 'wplr_sync_dashboard' ] );
			$is_meowapps_dashboard = $page === 'meowapps-main-menu';
			//if ( $is_meowapps_dashboard || $is_wplr_sync_screen || $is_media_library ) {
				add_action( 'admin_enqueue_scripts', array( $this, 'admin_enqueue_scripts' ) );
			//}
		}
	}

	private function wp_ajax_auth_check( $action ) {
		$nonce = apply_filters( 'wplr_sync_ajax_nonce', check_ajax_referer( $action ) );
		if ( !$nonce ) {
			wp_send_json_error( 'Invalid nonce' );
		}

		$user_can = apply_filters( 'wplr_sync_ajax_user_can', current_user_can( 'manage_options' ) );
		if ( !$user_can ) {
			wp_send_json_error( 'You do not have sufficient permissions to perform this action.' );
		}
	}

	function admin_enqueue_scripts() {

		// Load the scripts
		$physical_file = WPLR_SYNC_PATH . '/app/index.js';
		$cache_buster = file_exists( $physical_file ) ? filemtime( $physical_file ) : WPLR_SYNC_VERSION;
		wp_register_script( 'pEngine-vendor', WPLR_SYNC_URL . 'app/vendor.js',
			['wp-element', 'wp-i18n'], $cache_buster
		);
		wp_register_script( 'pEngine', WPLR_SYNC_URL . 'app/index.js',
			['pEngine-vendor', 'wp-i18n'], $cache_buster
		);
		wp_set_script_translations( 'pEngine', 'wplr-sync' );
		wp_enqueue_script('pEngine' );

		// Load the fonts
		wp_register_style( 'meow-neko-ui-lato-font', '//fonts.googleapis.com/css2?family=Lato:wght@100;300;400;700;900&display=swap');
		wp_enqueue_style( 'meow-neko-ui-lato-font' );

		global $wplr;
		$screen = get_current_screen();
		$collections = $wplr->read_collections_recursively();

		// Localize and options
		$col_id = isset($_GET['col_id']) ? (int)$_GET['col_id'] : 0;
		wp_localize_script( 'pEngine', 'pEngine', array_merge( [
			'api_url' => rest_url( 'wplr-sync/v1' ),
			'rest_url' => rest_url(),
			'plugin_url' => WPLR_SYNC_URL,
			'prefix' => WPLR_SYNC_PREFIX,
			'domain' => WPLR_SYNC_DOMAIN,
			'is_pro' => true,
			'is_registered' => true,
			'rest_nonce' => wp_create_nonce( 'wp_rest' ),
			'hierarchy' => $collections,
			'isMediaLibrary' => $screen->base === 'upload',
			'col_id' => $col_id,
			'media_library' => get_option( 'wplr_media_library' ),
			'media_modals' => get_option( 'wplr_media_modals' ),
		], $this->get_all_options() ) );
	}

	function is_registered() {
		return true;
	}

	function list_options() {
		return array(
			'wplr_use_taken_date' => false,
			'wplr_upload_folder' => false,
			'wplr_filename_accents' => false,
			'wplr_enable_keywords' => false,
			'wplr_sync_keywords' => '',
			'wplr_library_show_hierarchy' => 'none',
			'wplr_public_api' => false,
			'wr2x_big_image_size_threshold' => false,
			'wplr_debugging_enabled' => false,
			'wplr_catch_errors' => false,
			'wplr_check_same_file' => false,
			'wplr_debuglogs' => false,
			'wplr_hide_extensions' => false,
			'wplr_protocol' => false,
			'wplr_library_show_filters' => false,
			'wplr_auth_token' => false,
			'wplr_qr' => null,
			'sync_keywords_options' => [],
			'troubles_issues' => [],
			'extensions' => [],
			'wplr_media_organizer' => false,
			'wplr_media_library' => false,
			'wplr_media_modals' => false,
		);
	}

	function get_all_options() {
		// sync_keywords_options
		$taxonomies = get_object_taxonomies( 'attachment' );
		array_unshift( $taxonomies, "" );

		// Troubleshooting (Potential issues)
		$troubles = new Meow_WPLR_Sync_Troubleshoot();
		$issues = $troubles->issues();

		// Extensions
		$extensions = apply_filters( 'wplr_extensions', [] );

		// Public API
		$public_api = get_option( 'wplr_public_api', false );
		$wplr_auth_token = get_transient( 'wplr_auth_token' );
		$wplr_qr = null;
		if ( $public_api ) {
			$home_url = function_exists( 'pll_home_url' ) ? pll_home_url() : get_home_url();
			if ( $wplr_auth_token === false ) {
				$wplr_auth_token = str_replace ( '|', '#', wp_generate_password( 12, false, false ) );
				set_transient( 'wplr_auth_token', $wplr_auth_token, YEAR_IN_SECONDS );
			}
			$wplr_qr = $home_url . '|' . $wplr_auth_token;
		} 
		elseif ( $wplr_auth_token !== false ) {
			delete_transient( 'wplr_auth_token' );
		}

		$options = $this->list_options();
		$current_options = array();
		foreach ( $options as $option => $default ) {
			if ( $option === 'wplr_public_api' ) {
				$current_options[$option] = $public_api;
			} elseif ( $option === 'wplr_auth_token' ) {
				$current_options[$option] = $wplr_auth_token;
			} elseif ( $option === 'wplr_qr' ) {
				$current_options[$option] = $wplr_qr;
			} elseif ( $option === 'sync_keywords_options' ) {
				$current_options[$option] = $taxonomies;
			} elseif ( $option === 'troubles_issues' ) {
				$current_options[$option] = $issues;
			} elseif ( $option === 'extensions' ) {
				$current_options[$option] = $extensions;
			} else {
				$current_options[$option] = get_option( $option, $default );
			}
		}
		return $current_options;
	}

	/**
	 * Outputs the auth token generator UI
	 * @param $user
	 */
	function auth_token_field( $user ) {
		?>
		<table class="form-table">
			<tr>
				<th><?php _e( 'Token for Photo Engine', 'wplr-sync' ); ?></th>
				<td id="wplr-auth-token-generator">
					<button class="button"><?php _e( 'Generate Token', 'wplr-sync' ); ?></button>
					<?php $token = get_user_meta( $user->ID, 'wplr_auth_token', true ); ?>
					<p class="description<?php if ( !$token ) echo ' no-token hidden'; ?>">Your token is <var class="token"><?php echo esc_html( $token ); ?></var></p>
				</td>
			</tr>
		</table>
		<script>
			(function ($) {
				var wrap = $('#wplr-auth-token-generator')
				wrap.find('button').on('click', function (ev) {
					ev.preventDefault()

					var $this = $(this) // The button itself
					if ($this.prop('disabled')) return false
					$this.prop('disabled', true)

					$.ajax(ajaxurl, {
						method: 'POST',
						dataType: 'json',
						data: {
							_ajax_nonce: '<?php echo wp_create_nonce( 'wplrsync_generate_auth_token' ); ?>',
							action: 'wplrsync_generate_auth_token'
						}

					}).always(function () {
						$this.prop('disabled', false)

					}).fail(function (err) {
						var msg = '<?php _e( 'Failed to generate an auth token due to the following reason:', 'wplr-sync' ); ?>' + '\n'
						msg += '"' + err.responseJSON.data + '"' + '\n'
						msg += 'Status: ' + err.status + ' ' + err.statusText + '\n'
						console.error(msg)
						// TODO: Show the error message on the front

					}).done(function (result) {
						var token = result.data.newToken
						wrap.find('var.token').text(token)
						wrap.find('.no-token.hidden').removeClass('hidden')
					})
				})
			})(jQuery)
		</script>
		<style>
			#wplr-auth-token-generator var.token {
				font-style: normal;
				font-family: monospace;
				color: green;
			}
		</style>
		<?php
	}

	/**
	 * Generates an auth token via ajax
	 * @uses $_POST['action']
	 * @uses $_POST['userId']
	 */
	function ajax_generate_auth_token() {
		if ( !check_ajax_referer( $_POST['action'] ) ) {
			wp_send_json_error( __( 'Invalid nonce', 'wplr-sync' ), 403 );
		}
		$userId = get_current_user_id();
		$user = get_userdata( $userId );
		if ( !$user ) {
			wp_send_json_error( __( 'You have to be logged in', 'wplr-sync' ), 401 );
		}
		try {
			$token = $this->wplr->generate_auth_token( $userId );
		}
		catch ( Exception $e ) {
			wp_send_json_error( __( 'Failed to save the auth token to DB', 'wplr-sync' ), 500 ); // I/O failure
		}
		wp_send_json_success( array ( 'newToken' => $token ) );
	}

	function common_url( $file ) {
		return plugin_dir_url( __FILE__ ) . ( '\/common\/' . $file );
	}

	function media_row_actions( $actions, $post ) {
		global $current_screen;
		if ( 'upload' != $current_screen->id ) {
			return $actions;
		}
		global $wpdb;
		$table_name = $wpdb->prefix . "lrsync";
		$res = $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $table_name WHERE wp_id = %d", $post->ID ) );
		if ( !empty( $res ) && isset( $actions['trash'] ) )
			$actions['trash'] = "Trash";
		return $actions;
	}

	function admin_menu() {
		$hide_extensions = get_option( 'wplr_hide_extensions' ) && !get_option( 'wplr_debugging_enabled' );

		// -- Debugging
		add_settings_section( 'wplr_settings_debug', null, null, 'wplr-settings-menu-debug' );
		add_settings_field( 'wplr_debugging_enabled', __( 'Debugging', 'wplr-sync' ),
			array( $this, 'admin_debugging_callback' ),'wplr-settings-menu-debug', 'wplr_settings_debug',
			array( "Enable" ) );
		add_settings_field( 'wplr_catch_errors', __( 'Catch Errors', 'wplr-sync' ),
			array( $this, 'admin_catch_errors_callback' ),'wplr-settings-menu-debug', 'wplr_settings_debug',
			array( "Enable" ) );
		add_settings_field( 'wplr_check_same_file', __( 'Avoid Double Processing', 'wplr-sync' ),
			array( $this, 'admin_check_same_file_callback' ),'wplr-settings-menu-debug', 'wplr_settings_debug',
			array( "Enable (BETA)" ) );
		add_settings_field( 'wplr_debuglogs', __( 'Advanced Logs', 'wplr-sync' ),
			array( $this, 'admin_debuglogs_callback' ), 'wplr-settings-menu-debug', 'wplr_settings_debug',
			array( "Enable" ) );
		register_setting( 'wplr-settings-debug', 'wplr_library_show_hierarchy' );
		register_setting( 'wplr-settings-debug', 'wplr_debuglogs' );
		register_setting( 'wplr-settings-debug', 'wplr_catch_errors' );
		register_setting( 'wplr-settings-debug', 'wplr_debugging_enabled' );
		register_setting( 'wplr-settings-debug', 'wplr_check_same_file' );
		register_setting( 'wplr-settings-debug', 'wplr_public_api' );

		add_submenu_page( 'meowapps-main-menu', 'Photo Engine', 'Photo Engine', 'manage_options',
			'wplr_sync_settings', array( $this, 'admin_settings' ) );

		// Debug
		if ( get_option( 'wplr_debugging_enabled' ) )
			add_submenu_page( 'meowapps-main-menu',
				__( 'Photo Engine Debug', 'wplr-sync' ),
				__( 'Photo Engine Debug', 'wplr-sync' ), 'manage_options',
				'wplrsync-debug-menu', array( $this, 'admin_debug' ) );
	}

	function admin_settings() {
		echo '<div id="wplr-sync-admin-settings"></div>';
	}

	/*
		OPTIONS
	*/

	function wplrsync_clean() {
		$this->wp_ajax_auth_check( 'wp_ajax_wplrsync_clean' );

		global $wpdb;
		$tbl_m = $wpdb->prefix . 'lrsync';
		$tbl_r = $wpdb->prefix . 'lrsync_relations';
		$tbl_c = $wpdb->prefix . 'lrsync_collections';
		$tbl_mt = $wpdb->prefix . 'lrsync_meta';
		try {
			do_action( 'wplr_clean' );
			$wpdb->query( "DELETE FROM $tbl_m WHERE wp_id NOT IN (SELECT ID FROM $wpdb->posts WHERE post_type = 'attachment')" );
			$wpdb->query( "DELETE FROM $tbl_r WHERE wp_id NOT IN (SELECT ID FROM $wpdb->posts WHERE post_type = 'attachment')" );
			$wpdb->query( "DELETE FROM $tbl_r WHERE wp_col_id NOT IN (SELECT wp_col_id FROM $tbl_c)" );
			$wpdb->query( "DELETE FROM $tbl_mt WHERE name = 'media_tag' AND id NOT IN (SELECT ID FROM $wpdb->posts WHERE post_type = 'attachment')" );
			echo json_encode( array( 'success' => true ) );
		}
		catch ( Exception $e ) {
			error_log( print_r( $e, true ) );
			echo json_encode( array( 'success' => false, 'message' => "An exception was caught and written in the PHP error logs." ) );
		}
		die();
	}



	function wplrsync_extensions_reset() {
		$this->wp_ajax_auth_check( 'wp_ajax_wplrsync_extensions_reset' );

		try {
			do_action( 'wplr_reset' );
			wp_send_json_success();
		} catch ( Exception $e ) {
			error_log( print_r( $e, true ) );
			wp_send_json_error( 'An exception was caught and written in the PHP error logs.' );
		}
	}

	function wplrsync_extensions_query() {
		$this->wp_ajax_auth_check( 'wp_ajax_wplrsync_extensions_query' );

		try {
			global $wplr;
			$task = $_POST['task'];
			if ( $task['action'] == 'add_collection' ) {
				if ( $task['is_folder'] )
					do_action( 'wplr_create_folder', (int)$task['wp_col_id'], (int)$task['wp_folder_id'], array( 'name' => $task['name'] ) );
				else
					do_action( 'wplr_create_collection', (int)$task['wp_col_id'], (int)$task['wp_folder_id'], array( 'name' => $task['name'] ) );
			}
			else if ( $task['action'] == 'remove_collection' ) {
				if ( $task['is_folder'] )
					do_action( 'wplr_remove_folder', (int)$task['wp_col_id'] );
				else
					do_action( 'wplr_remove_collection', (int)$task['wp_col_id'] );
			}
			else if ( $task['action'] == 'add_media' )
				do_action( 'wplr_add_media_to_collection', (int)$task['wp_id'], (int)$task['wp_col_id'] );
			else if ( $task['action'] == 'remove_media' )
				do_action( 'wplr_remove_media_from_collection', (int)$task['wp_id'], (int)$task['wp_col_id'] );
			else if ( $task['action'] == 'add_tag' ) {
				$pTagParent = $wplr->get_meta( 'tag_parent', (int)$task['id'] );
				do_action( 'wplr_add_tag', (int)$task['id'], $task['name'], $pTagParent );
			}
			else if ( $task['action'] == 'remove_tag' )
				do_action( 'wplr_remove_tag', (int)$task['id'] );
			else if ( $task['action'] == 'update_tag' )
				do_action( 'wplr_update_tag', (int)$task['id'], $task['name'], (int)$task['parent'] );
			else if ( $task['action'] == 'add_media_tag' )
				do_action( 'wplr_add_media_tag', (int)$task['wp_id'], (int)$task['id'] );
			else if ( $task['action'] == 'remove_media_tag' )
				do_action( 'wplr_remove_media_tag', (int)$task['wp_id'], (int)$task['id'] );

			echo json_encode( array( 'success' => true ) );
		}
		catch ( Exception $e ) {
			error_log( print_r( $e, true ) );
			echo json_encode( array( 'success' => false, 'message' => "An exception was caught and written in the PHP error logs." ) );
		}
		die();
	}

	function wplrsync_extensions_init() {
		$this->wp_ajax_auth_check( 'wp_ajax_wplrsync_extensions_init' );

		global $wpdb, $wplr;
		$isRemoval = isset( $_POST['isRemoval'] ) && $_POST['isRemoval'] == 1;
		$tbl_m = $wpdb->prefix . 'lrsync';
		$tbl_r = $wpdb->prefix . 'lrsync_relations';
		$tbl_t = $wpdb->prefix . 'lrsync_meta';

		$tasks = array();

		// Tags
		$tags = $wpdb->get_results( $wpdb->prepare( "SELECT id as id, value as name FROM $tbl_t WHERE name = %s", 'tag_name' ), ARRAY_A );
		foreach ( $tags as $tag )
			array_push( $tasks, array_merge( array( 'action' => $isRemoval ? 'remove_tag' : 'add_tag' ), $tag ) );

		// Tag's Parents
		if ( !$isRemoval ) {
			$tags = $wpdb->get_results( $wpdb->prepare( "SELECT m1.id as id, m1.value as name, m2.value as parent
				FROM $tbl_t m1
				JOIN $tbl_t m2 ON m2.id = m1.id AND m2.name = %s
				WHERE m1.name = %s", 'tag_parent', 'tag_name' ), ARRAY_A );

			foreach ( $tags as $tag )
				array_push( $tasks, array_merge( array( 'action' => 'update_tag' ), $tag ) );
		}

		// Collections
		$collections = $wplr->read_collections_recursively( null, array(), $isRemoval );
		$tasks = array_merge( $tasks, $collections );

		// Photos
		foreach ( $collections as $c ) {
			if ( !$c['is_folder'] ) {
				$photos = $wpdb->get_results( $wpdb->prepare( "SELECT wp_id, wp_col_id, sort FROM $tbl_r WHERE wp_col_id = %d ORDER BY sort", $c['wp_col_id'] ), ARRAY_A );
				foreach ( $photos as $p )
					array_push( $tasks, array_merge( array( 'action' => $isRemoval ? 'remove_media' : 'add_media' ), $p ) );
			}
		};

		// Media Tags
		$tags = $wpdb->get_results( $wpdb->prepare( "
			SELECT id as wp_id, value as id
			FROM $tbl_t
			WHERE name = %s", 'media_tag' ), ARRAY_A );
		foreach ( $tags as $tag )
			array_push( $tasks, array_merge( array( 'action' => $isRemoval ? 'remove_media_tag' : 'add_media_tag' ), $tag ) );
		echo json_encode( array( 'success' => true, 'data' => $isRemoval ? $tasks : array_reverse( $tasks ) ) );
		die();
	}

	function admin_debugging_callback( $args ) {
		$html = '<input type="checkbox" id="wplr_debugging_enabled" name="wplr_debugging_enabled" value="1" ' .
			checked( 1, get_option( 'wplr_debugging_enabled' ), false ) . '/>';
		$html .= '<label for="wplr_debugging_enabled"> '  . $args[0] . '</label><br>';
		$html .= '<span class="description">' .
			__( 'Add a Debugging menu in Photo Engine. For advanced users only.', 'wplr-sync' ) . '</span>';
		echo $html;
	}

	function admin_catch_errors_callback( $args ) {
		$html = '<input type="checkbox" id="wplr_catch_errors" name="wplr_catch_errors" value="1" ' .
			checked( 1, get_option( 'wplr_catch_errors' ), false ) . '/>';
		$html .= '<label for="wplr_catch_errors"> '  . $args[0] . '</label><br>';
		$html .= '<span class="description">' .
			__( 'Errors (from other plugins, themes, etc) happening during the Photo Engine process will be caught to avoid operations to fail.', 'wplr-sync' ) . '</span>';
		echo $html;
	}

	function admin_check_same_file_callback( $args ) {
		$html = '<input type="checkbox" id="wplr_check_same_file" name="wplr_check_same_file" value="1" ' .
			checked( 1, get_option( 'wplr_check_same_file' ), false ) . '/>';
		$html .= '<label for="wplr_check_same_file"> '  . $args[0] . '</label><br>';
		$html .= '<span class="description">' .
			__( 'Avoid processing if the new file is the same as the old one, to avoid thumbnails to be generated again, optimizers, etc.', 'wplr-sync' ) . '</span>';
		echo $html;
	}

	function admin_debuglogs_callback( $args ) {
		$clearlogs = isset ( $_GET[ 'clearlogs' ] ) ? $_GET[ 'clearlogs' ] : 0;
		if ( $clearlogs ) {
			if ( file_exists( plugin_dir_path( __FILE__ ) . '/wplr-sync.log' ) ) {
				unlink( plugin_dir_path( __FILE__ ) . '/wplr-sync.log' );
			}
		}
		$html = '<input type="checkbox" id="wplr_debuglogs" name="wplr_debuglogs" value="1" ' .
			checked( 1, get_option( 'wplr_debuglogs' ), false ) . '/>';
		$html .= '<label for="wplr_debuglogs"> '  . $args[0] . '</label><br>';
		$html .= '<span class="description">' . __( 'Create an internal log file. For advanced users only.', 'wplr-sync' );
		if ( file_exists( plugin_dir_path( __FILE__ ) . '/wplr-sync.log' ) ) {
			$html .= sprintf( __( '<br />The <a target="_blank" href="%s/wplr-sync.log">log file</a> is available. You can also <a href="?page=wplr-main-menu&clearlogs=true">clear</a> it.', 'wplr-sync' ), plugin_dir_url( __FILE__ ) );
		}
		$html .= '</span>';
		echo $html;
	}

	function display_hierarchy( $action ) {
		$mode = isset( $_POST['action'] ) && $action == "keywords" ? 'keywords' : 'hierarchy';
		$delete_collection = isset( $_POST['delete_collection'] ) ? $_POST['delete_collection'] : null;
		$delete_keyword = isset( $_POST['delete_keyword'] ) ? $_POST['delete_keyword'] : null;
		$hasDeleted = false;

		if ( $delete_collection ) {
			global $wplr;
			$wplr->delete_collection( $delete_collection );
			$hasDeleted = true;
		}
		if ( $delete_keyword ) {
			global $wplr;
			$wplr->delete_keyword( $delete_keyword );
			$hasDeleted = true;
		}

		echo "<br /><br />";
		$hierarchy = $mode == 'keywords' ? $this->wplr->get_keywords_hierarchy() : $this->wplr->get_hierarchy();

		function display_internal_hierarchy( $hierarchy, $level = 0, $mode = '', $hasDeleted = false ) {
			global $wpdb;
			$tbl_r = $wpdb->prefix . 'lrsync_relations';
			$page = empty( $_GET['page'] ) ? 'wplr-collections-tags-menu' : $_GET['page'];
			echo '<div class="hierarchy-level-' . $level . '">';
			if ( $level > 0 )
				echo '<div style="margin-left: 10px; border-left: 1px dotted gray; padding-left: 10px;">';
			foreach ( $hierarchy as $c ) {

				if ( $mode == 'keywords' ) {
					echo '<div class="wplr-elem wplr-keyword" wplr-elem-type="keyword" wplr-elem-id="' .
						$c['id'] . '"	wplr-elem-name="' . $c['name'] . '"><span class="dashicons dashicons-carrot"></span> <b>' .
						$c['name'] . '</b> <small>(ID: ' . $c['id'] . ', Photos: ' . $c['count'] . ')</small>';
					echo '<form action="" method="post" style="display: inline;">
						<input type="hidden" name="page" value="' . $page . '">
						<input type="hidden" name="action" value="' . $mode . '">';
					wp_nonce_field( 'wplr_debug_action' );
					echo '<small class="wplr_delete" style="display: ' . ( $hasDeleted ? 'inline' : 'none' ) . ';">
						<button type="submit" name="delete_keyword" value="' . $c['id'] . '" class="btn-link">' .
						__( 'Delete', 'wplr-sync' ) . '</button>
						</small></form>';
					echo '</div>';
				}
				else {
					$type = $c['type'] == 'folder' ? '<span class="dashicons dashicons-category"></span>' : '<span class="dashicons dashicons-format-gallery"></span>';
					echo '<div class="wplr-elem wplr-' . $c['type']
							. '" wplr-elem-type="' . $c['type'] . '" wplr-elem-id="' . $c['id'] . '" wplr-elem-name="' . $c['name'] . '">'
						. $type . ' ' . $c['name'] . ' <small>(ID: ' . $c['id'] . ')</small>';

					echo '<form action="" method="post" style="display: inline;">
						<input type="hidden" name="page" value="' . $page. '">';
					wp_nonce_field( 'wplr_debug_action' );
					echo '<small class="wplr_delete" style="display: none;">
						<button type="submit" name="delete_collection" value="' . $c['id'] . '" class="btn-link">' .
						__( 'Delete', 'wplr-sync' ) . '</button>
						</small></form>';
					echo '</div>';
				}

				if ( ( $mode == 'hierarchy' && $c['type'] == 'folder' ) ||
					( $mode == 'keywords' && count( $c['children'] ) > 0 ) ) {
					display_internal_hierarchy( $c['children'], $level + 1, $mode, $hasDeleted );
				}
				else {
					if ( $mode == 'hierarchy' ) {
						$photos = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM $tbl_r WHERE wp_col_id = %d ORDER BY sort LIMIT 25", $c['id'] ), OBJECT );
						if ( count( $photos ) > 0 ) {
							$count = $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $tbl_r WHERE wp_col_id = %d", $c['id'] ) );
							echo '<div style="margin-left: 0px; padding: 5px 0px; margin-top: 2px; margin-bottom: 5px; border-top: 1px solid lightgray;">';
							echo '<div style="float: left; margin-right: 2px; width: 32px; height: 26px; background: #444444; text-align: center; padding-top: 6px; font-size: 10px; color: white;">' . $count . '</div>';
							foreach ( $photos as $photo ) {
								$src = wp_get_attachment_image_src( $photo->wp_id, 'thumbnail' );
								if(!$src ){
									echo '<div><span class="dashicons dashicons-no" style="float: left; margin-right: 2px; margin-bottom: 2px; font-size: 32px; line-height: 32px; color: red;"></span></div>';
									continue;
								}
								echo '<div><a href="media.php?attachment_id=' . $photo->wp_id . '&action=edit"><img style="float: left; margin-right: 2px; margin-bottom: 2px;" width="32" height="32" src="' . $src[0] . '"></a></div>';
							}
							echo '<div style="clear: both;"></div></div>';
						}
					}
				}
			}
			if ( $level > 0 )
				echo '</div>';
			echo '</div>';
		}
		display_internal_hierarchy( $hierarchy, 0, $mode, $hasDeleted );
		?>
		<script>
		function wplr_toggle_delete() {
			jQuery('.wplr_delete').toggle();
		}
		jQuery('.wplr-elem').hover(function () {
			var id = jQuery(this).attr('wplr-elem-id');
			var ids = [];
			var name = jQuery(this).attr('wplr-elem-name');
			var type = jQuery(this).attr('wplr-elem-type');
			var content = "";

			if (type == 'folder') {
				jQuery(this).next('div').find('.wplr-collection').each(function(i, v) {
					ids.push(jQuery(v).attr('wplr-elem-id'));
				});
				id = ids.join(',');
			}
			if (type == 'keyword') {
				ids.push(id);
				jQuery(this).next('div').find('.wplr-keyword').each(function(i, v) {
					ids.push(jQuery(v).attr('wplr-elem-id'));
				});
				id = ids.join(',');
			}

			if (type == 'collection' || type == 'folder') {
				content += 'Here are my photos about <i>' + name + ':</i><br />';
				content += '[gallery wplr-collection' + (ids.length > 1 ? 's' : '') + '="' + id + '"]';
			}
			else if (type == 'keyword') {
				content += 'Here are my photos about <i>' + name + ':</i><br />';
				content += '[gallery wplr-keyword' + (ids.length > 1 ? 's' : '') + '="' + id + '"]';

				// content += '<i>Keywords are not supported yet, if you are interested in this feature please come on the forum of the Meow Gallery and ask for it :) Here: <a href="https://wordpress.org/support/plugin/meow-gallery">Meow Gallery Support Forum</a><i>';
			}
			jQuery('#shortcode-preview-code').html(content);
			jQuery('#shortcode-preview-code').show();
			console.log(jQuery(this));
		});
		</script>
		<p>
			<small><input type="checkbox" name="unlocked" <?= ( $hasDeleted ? 'checked' : '' ) ?> onclick="wplr_toggle_delete()">
				<?php _e( 'Unlock <b>delete</b>', 'wplr-sync' ) ?>
			</small>
		</p>
		<?php
	}

	function admin_css() {
		?>
		<style>

			.left {
				width: 450px;
			}

			.right {
				position: absolute;
				left: 460px;
				right: 10px;
			}

			.left-75 {
				width: 60%;
			}

			.right-25 {
				position: absolute;
				width: 34%;
				right: 20px;
			}

			.wplr-collection, .wplr-folder, .wplr-keyword {
				cursor: pointer;
			}

			.shortcode-preview {
				margin-bottom: 20px;
		    background: #0085ba;
		    padding: 10px;
		    font-size: 12px;
		    word-break: break-all;
		    color: white;
		    margin-top: -10px;
			}

			h3 {
				margin-bottom: 5px;
			}

			p {
				margin-top: 0px;
				margin-bottom: 10px;
			}

			.wplrsync-form {
				border: 1px solid lightgrey;
				padding: 5px;
				background: white;
				border-radius: 5px;
				width: 420px;
			}

			th {
				text-align: left;
			}

			#wpfooter {
				display: none;
			}

		</style>
		<?php
	}

	function display_ads() {
		return !get_option( 'meowapps_hide_ads', false );
	}

	function display_title( $title = "Meow Apps",
		$author = "By <a style='text-decoration: none;' href='https://meowapps.com' target='_blank'>Jordy Meow</a>" ) {
		if ( !empty( $this->prefix ) && $title !== "Meow Apps" )
			$title = apply_filters( $this->prefix . '_plugin_title', $title );
		if ( $this->display_ads() ) {
		}
		?>
		<h1 style="line-height: 16px;">
			<img width="42" style="margin-right: 10px; float: left; position: relative; top: -5px;"
				src="<?php echo self::$logo ?>"><?php echo $title; ?><br />
			<span style="font-size: 12px"><?php echo $author; ?></span>
		</h1>
		<div style="clear: both;"></div>
		<?php
	}

	function admin_debug() {
		if ( !current_user_can( 'manage_options' ) )  {
			wp_die( __( 'You do not have sufficient permissions to access this page.' ) );
		}

		// HEADER
		$this->admin_css();
		?>
		<div class="wrap" >

			<?php echo $this->display_title( __( 'Debugging', 'wplr-sync' ) . " | Photo Engine" ); ?>
			<p>Those tools should be used for debugging purposed. Be careful when you are using them, especially the colored buttons (usually blue).</p>
		<?php

		global $wpdb;
		$table_name = $wpdb->prefix . "lrsync";

		if ( !isset( $_POST['action'] ) && isset( $_GET['action'] ) ) {
			$_POST['action'] = $_GET['action'];
		}

		if ( isset( $_POST['action'] ) ) {

			// CSRF Protection: Verify nonce for POST requests
			if ( !isset( $_POST['_wpnonce'] ) || !wp_verify_nonce( $_POST['_wpnonce'], 'wplr_debug_action' ) ) {
				wp_die( __( 'Security check failed. Please try again.', 'wplr-sync' ) );
			}

			$action = $_POST['action'];
			if ( $action == "reset" ) {
				$this->wplr->reset_db();
				echo "<div class='updated'><p>" .
					__( 'The database was reset.', 'wplr-sync' ) .
					"</p></div>";
			}
			else if ( $action == "duplicates" ) {
				$duplicates = $this->wplr->list_duplicates();
			}
			else if ( $action == "scan" ) {
				$unlinks = $this->wplr->list_unlinks();
			}
			else if ( $action == "list" ) {
				$list = $this->wplr->list_sync_media();
			}
			else if ( $action == "link" ) {
				if ( $this->wplr->link_media( $_POST['lr_id'], $_POST['wp_id'] ) ) {
					echo "<div class='updated'><p>" .
						__( 'Link successful.', 'wplr-sync' ) .
						"</p></div>";
				}
				else {
					echo "<div class='error'><p>" . $this->wplr->get_error()->message . "</p></div>";
				}
			}
			else if ( $action == "linkinfo_upload" ) {
				if ( isset( $_FILES['file'], $_FILES['file']['tmp_name'] ) && !empty( $_FILES['file']['tmp_name'] ) ) {
					$tmp_path = $_FILES['file']['tmp_name'];
					$linkinfo = $this->wplr->linkinfo_upload( $tmp_path, null );
				}
				else {
					$linkinfo = $this->wplr->linkinfo_media( $_POST['wp_id'] );
				}
				if ( $linkinfo )
					echo "<div class='updated'><p>" .
						__( 'Link info retrieved.', 'wplr-sync' )
						. "</p></div>";
				else
					echo "<div class='error'><p>" . $this->wplr->get_error()->message . "</p></div>";
			}
			else if ( $action == "sync" ) {
				$tmp_path = $_FILES['file']['tmp_name'];
				$lrinfo = new Meow_WPLR_Sync_LRInfo();
				$lrinfo->lr_id = $_POST['lr_id'] == "" ? -1 : $_POST['lr_id'];
				$lrinfo->lr_file = $_FILES['file']['name'];
				$lrinfo->lr_title = isset( $_POST['title'] ) ? $_POST['title'] : "";
				$lrinfo->lr_caption = $_POST['caption'];
				$lrinfo->lr_desc = isset( $_POST['desc'] ) ? $_POST['desc'] : "";
				$lrinfo->lr_alt_text = isset( $_POST['altText'] ) ? $_POST['altText'] : "";
				$lrinfo->sync_title = isset( $_POST['syncTitle'] ) && $_POST['syncTitle'] == 'on';
				$lrinfo->sync_caption = isset( $_POST['syncCaption'] ) && $_POST['syncCaption'] == 'on';
				$lrinfo->sync_desc = isset( $_POST['syncDesc'] ) && $_POST['syncDesc'] == 'on';
				$lrinfo->sync_alt_text = isset( $_POST['syncAltText'] ) && $_POST['syncAltText'] == 'on';
				$lrinfo->type = $_FILES['file']['type'];
				if ( $this->wplr->sync_media( $lrinfo, $tmp_path ) ) {
					echo "<div class='updated'><p>";
					echo sprintf( __( 'Lr ID %d was synchronized with the attachment.', 'wplr-sync' ), $_POST['lr_id'] );
					echo "</p></div>";
				}
				else
					echo "<div class='error'><p>" . $this->wplr->get_error()->message . "</p></div>";

			}
			else if ( $action == "unlink" ) {
				if ( $this->wplr->unlink_media( $_POST['lr_id'], $_POST['wp_id'] ) ) {
					echo "<div class='updated'><p>";
					echo sprintf( __( 'Media ID %d was unlinked.', 'wplr-sync' ), $_POST['lr_id'] );
					echo "</p></div>";
				}
				else
					echo "<div class='error'><p>" . $this->wplr->get_error()->message . "</p></div>";
			}
			else if ( $action == "remove" ) {
				if ( $this->wplr->delete_media( $_POST['lr_id'] ) ) {
					echo "<div class='updated'><p>";
					echo sprintf( __( 'Media ID %d was removed.', 'wplr-sync' ), $_POST['lr_id'] );
					echo "</p></div>";
				}
				else
					echo "<div class='error'><p>" . $this->wplr->get_error()->message . "</p></div>";
			}
			else if ( $action != 'api' && $action != 'keywords' && $action != 'hierarchy'  ) {
				echo "<div class='error'<p>Unknown action.</p></div>";
			}

		}

		// CONTENT & FORMS
		?>
			<div class="right">

				<h3><?php _e( 'Display', 'wplr-sync' ); ?></h3>
				<p class="buttons">
					<form style="float: left; margin-right: 5px;" method="post" action="">
						<input type="hidden" name="action" value="hierarchy">
						<?php wp_nonce_field( 'wplr_debug_action' ); ?>
						<input type="submit" name="submit" id="submit" class="button" value="Show Hierarchy">
					</form>
					<form style="float: left; margin-right: 5px;" method="post" action="">
						<input type="hidden" name="action" value="keywords">
						<?php wp_nonce_field( 'wplr_debug_action' ); ?>
						<input type="submit" name="submit" id="submit" class="button" value="Show Keywords">
					</form>
					<form style="float: left; margin-right: 5px;" method="post" action="">
						<input type="hidden" name="action" value="list">
						<?php wp_nonce_field( 'wplr_debug_action' ); ?>
						<input type="submit" name="submit" id="submit" class="button" value="List Linked">
					</form>
					<form style="float: left; margin-right: 5px;" method="post" action="">
						<input type="hidden" name="action" value="scan">
						<?php wp_nonce_field( 'wplr_debug_action' ); ?>
						<input type="submit" name="submit" id="submit" class="button" value="List Unlinked">
					</form>
					<form style="float: left; margin-right: 5px;" method="post" action="">
						<input type="hidden" name="action" value="duplicates">
						<?php wp_nonce_field( 'wplr_debug_action' ); ?>
						<input type="submit" name="submit" id="submit" class="button" value="List Duplicates">
					</form>
					<!-- <form style="float: left; margin-right: 5px;" method="post" action="">
						<input type="hidden" name="action" value="api">
						<input type="submit" name="submit" id="submit" class="button" value="API Ping">
					</form> -->
				</p>
				<br />

				<?php
					if ( isset( $_POST['action'] ) && $action == "scan" ) {
						echo '<br /><h3>' . __( 'Unlinked Media', 'wplr-sync' ) . '</h3>';
						echo '<pre>';
						print_r( $unlinks );
						echo '</pre>';
					}
					else if ( isset( $_POST['action'] ) && $action == "list" ) {
						echo '<br /><h3>' . __( 'Linked Media', 'wplr-sync' ) . '</h3>';
						echo '<pre>';
						print_r( $list );
						echo '</pre>';
					}
					else if ( isset( $_POST['action'] ) && $action == "linkinfo_upload" ) {
						echo '<pre>';
						print_r( $linkinfo );
						echo '</pre>';
					}
					else if ( isset( $_POST['action'] ) && $action == "duplicates" ) {
						echo '<br /><h3>' . __( 'Duplicates', 'wplr-sync' ) . '</h3>';
						echo '<pre>';
						print_r( $duplicates );
						echo '</pre>';
					}
					else if ( isset( $_POST['action'] ) && $action == "api" ) {
						$boundary = wp_generate_password(24);
						$response = wp_remote_post( admin_url( 'admin-ajax.php' ),
							array(
								'headers' => array( 'content-type' => 'multipart/form-data; boundary=' . $boundary ),
								'body' => array( 'action' => 'lrsync_api', 'isAjax' => 1, 'data' => '' )
						  )
						);
						echo '<br /><h3>' . __( 'API Response', 'wplr-sync' ) . '</h3>';
						echo '<pre>';
						print_r( $response );
						echo '</pre>';
					}
					else {
						$this->display_hierarchy( isset( $_POST['action'] ) ? $action : null );
					}
				?>
			</div>

			<div class="left">
				<h3><?php _e( 'Link Info', 'wplr-sync' ) ?></h3>
				<p><?php _e( 'Link info for either a WP ID <b>or</b> the Uploaded File.', 'wplr-sync' ) ?></p>
				<form class="wplrsync-form" method="post" action="" enctype="multipart/form-data">
					<input type="hidden" name="action" value="linkinfo_upload">
					<?php wp_nonce_field( 'wplr_debug_action' ); ?>
					<table>
						<tr>
							<th scope="row"><label for="wp_id">WP ID</label></th>
							<td><input name="wp_id" type="text" id="wp_id" value="" class="regular-text code"></td>
						</tr>
						<tr>
							<th scope="row"><label for="file">File</label></th>
							<td><input name="file" type="file" id="file"></td>
						</tr>
						<tr>
							<th scope="row"></th>
							<td><input type="submit" name="submit" id="submit" class="button" value="Check"></td>
						</tr>
					</table>
				</form>

				<h3><?php _e( 'Link', 'wplr-sync' ) ?></h3>
				<p><?php _e( 'Will link the WP Media ID to the Lr ID.', 'wplr-sync' ) ?></p>
				<form class="wplrsync-form" method="post" action="" enctype="multipart/form-data">
					<input type="hidden" name="action" value="link">
					<?php wp_nonce_field( 'wplr_debug_action' ); ?>
					<table>
						<tr>
							<th scope="row"><label for="lr_id">Lr ID</label></th>
							<td><input name="lr_id" type="text" id="lr_id" value="" class="regular-text code"></td>
						</tr>
						<tr>
							<th scope="row"><label for="wp_id">Media ID</label></th>
							<td><input name="wp_id" type="text" id="wp_id" value="" class="regular-text code"></td>
						</tr>
						<tr>
							<th scope="row"></th>
							<td><input type="submit" name="submit" id="submit" class="button button-primary" value="Link Media ID + Lr ID"></td>
						</tr>
					</table>

				</form>

				<h3><?php _e( 'Unlink', 'wplr-sync' ) ?></h3>
				<p><?php _e( 'Will unlink the media.', 'wplr-sync' ) ?></p>
				<form class="wplrsync-form" method="post" action="">
					<input type="hidden" name="action" value="unlink">
					<?php wp_nonce_field( 'wplr_debug_action' ); ?>
					<table>
						<tr>
							<th scope="row"><label for="lr_id">Lr ID</label></th>
							<td><input name="lr_id" type="text" id="lr_id" value="" class="regular-text code"></td>
						</tr>
						<tr>
							<th scope="row"><label for="wp_id">Media ID</label></th>
							<td><input name="wp_id" type="text" id="wp_id" value="" class="regular-text code"></td>
						</tr>
						<tr>
							<th scope="row"></th>
							<td><input type="submit" name="submit" id="submit" class="button button-primary" value="Unlink"></td>
						</tr>
					</table>
				</form>

				<h3><?php _e( 'Sync', 'wplr-sync' ) ?></h3>
				<p><?php _e( 'Will create the entry if doesn\'t exist, will update it if exists.', 'wplr-sync' ) ?></p>
				<form class="wplrsync-form" method="post" action="" enctype="multipart/form-data">
					<input type="hidden" name="action" value="sync">
					<?php wp_nonce_field( 'wplr_debug_action' ); ?>
					<table>
						<tr>
							<th scope="row"><label for="lr_id">Lr ID</label></th>
							<td><input name="lr_id" type="text" id="lr_id" value="" class="regular-text code"></td>
						</tr>
						<tr>
							<th scope="row"><label for="title">Title</label></th>
							<td><input name="title" type="text" id="title" class="regular-text code"></td>
						</tr>
						<tr>
							<th scope="row"><label for="title">Caption</label></th>
							<td><input name="caption" type="text" id="caption" class="regular-text code"></td>
						</tr>
						<tr>
							<th scope="row"><label for="title">Desc</label></th>
							<td><input name="desc" type="text" id="desc" class="regular-text code"></td>
						</tr>
						<tr>
							<th scope="row"><label for="title">Alt</label></th>
							<td><input name="altText" type="text" id="altText" class="regular-text code"></td>
						</tr>
						<tr>
							<th scope="row"><label for="file">File</label></th>
							<td><input name="file" type="file" id="file"></td>
						</tr>
						<tr>
							<th scope="row"><label for="sync">Sync</label></th>
							<td>
								<label><input type="checkbox" id="syncTitle" name="syncTitle">Title</label>
								<label><input type="checkbox" id="syncCaption" name="syncCaption">Caption</label>
								<label><input type="checkbox" id="syncDesc" name="syncDesc">Desc</label>
								<label><input type="checkbox" id="syncAltText" name="syncAltText">Alt</label>
							</td>
						</tr>
						<tr>
							<th scope="row"></th>
							<td><input type="submit" name="submit" id="submit" class="button button-primary" value="Sync Media"></td>
						</tr>
					</table>
				</form>

				<h3><?php _e( 'Remove', 'wplr-sync' ) ?></h3>
				<p><?php _e( 'Will remove the media.', 'wplr-sync' ) ?></p>
				<form class="wplrsync-form" method="post" action="">
					<input type="hidden" name="action" value="remove">
					<?php wp_nonce_field( 'wplr_debug_action' ); ?>
					<table>
						<tr>
							<th scope="row"><label for="lr_id">Lr ID</label></th>
							<td><input name="lr_id" type="text" id="lr_id" value="" class="regular-text code"></td>
						</tr>
						<tr>
							<th scope="row"></th>
							<td><input type="submit" name="submit" id="submit" class="button button-primary" value="Remove Media"></td>
						</tr>
					</table>
				</form>

				<h3><?php _e( 'Actions', 'wplr-sync' ) ?></h3>
				<p class="buttons">
					<?php _e( 'Be careful. Those buttons are dangerous.', 'wplr-sync' ) ?>
					<form style="margin-right: 5px;" method="post" action="">
						<input type="hidden" name="action" value="reset">
						<?php wp_nonce_field( 'wplr_debug_action' ); ?>
						<input type="submit" name="submit" id="submit" class="button button-primary"
							value="<?php _e( 'Reset Photo Engine DB', 'wplr-sync' ) ?>">
					</form>
				</p>

			</div>
		</div>
	</div>
		<?php
	}

	// Add metabox for format warning on media edit page
	function add_format_warning_metabox() {
		global $post;
		if ( $post && $post->post_type === 'attachment' ) {
			// Check if this media has a format mismatch
			global $wplr;
			$mismatch_info = $wplr->check_format_mismatch( $post->ID );
			if ( $mismatch_info && $mismatch_info['has_mismatch'] ) {
				add_meta_box(
					'wplr_format_warning',
					__( 'Format Notice', 'wplr-sync' ),
					array( $this, 'format_warning_metabox_content' ),
					'attachment',
					'side',
					'default'
				);
			}
		}
	}

	// Display format warning content
	function format_warning_metabox_content( $post ) {
		global $wplr;
		$mismatch_info = $wplr->check_format_mismatch( $post->ID );
		if ( $mismatch_info && $mismatch_info['has_mismatch'] ) {
			?>
			<div style="padding: 10px; background: #fff3cd; border: 1px solid #ffeeba; border-radius: 4px;">
				<p style="margin: 0 0 10px 0;">
					<strong>⚠️ <?php _e( 'Format Mismatch Detected', 'wplr-sync' ); ?></strong>
				</p>
				<p style="margin: 0 0 10px 0; font-size: 13px;">
					<?php 
					printf( 
						__( 'This file has a .%s extension but contains %s data.', 'wplr-sync' ), 
						esc_html( $mismatch_info['file_extension'] ), 
						esc_html( strtoupper( $mismatch_info['actual_format'] ) ) 
					); 
					?>
				</p>
				<p style="margin: 0 0 8px 0; font-size: 12px; color: #666;">
					<?php _e( 'This happens when you change export formats in Lightroom after photos have already been published. Due to Lightroom SDK limitations, there is no perfect solution to preserve the original format during re-exports.', 'wplr-sync' ); ?>
				</p>
				<p style="margin: 0; font-size: 12px; color: #666;">
					<strong><?php _e( 'Good news:', 'wplr-sync' ); ?></strong> <?php _e( 'Browsers detect the actual format from the file content, not the extension, so your images will display correctly.', 'wplr-sync' ); ?>
				</p>
				<p style="margin: 8px 0 0 0; font-size: 12px; color: #666;">
					<?php 
					printf( 
						__( 'If you want to fix the file extensions, you can use the <a href="%s" target="_blank">Media File Renamer</a> plugin.', 'wplr-sync' ),
						'https://wordpress.org/support/plugin/media-file-renamer/'
					); 
					?>
				</p>
			</div>
			<?php
		}
	}
}

?>
