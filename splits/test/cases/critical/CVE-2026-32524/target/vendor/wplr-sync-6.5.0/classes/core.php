<?php

class Meow_WPLR_Sync_Core {
	private $error;
	public $admin = null;
	public $is_rest = false;
	public $is_cli = false;
	public $site_url = null;
	
	public $cached_collections = null;

	public function __construct() {
		$this->site_url = get_site_url();
		$this->is_rest = MeowKit_WPLR_Helpers::is_rest();
		$this->is_cli = defined( 'WP_CLI' ) && WP_CLI;
		add_action( 'delete_attachment', array( $this, 'delete_attachment' ) );
		add_filter( 'manage_media_columns', array( $this, 'manage_media_columns' ) );
		add_filter( 'shortcode_atts_gallery', array( $this, 'gallery_images_shortcode' ), 10, 3 );
		add_filter( 'shortcode_atts_collection', array( $this, 'collection_images_shortcode' ), 10, 3 );
		//add_filter( 'foogallery_shortcode_atts', array( $this, 'foogallery_shortcode' ), 10, 1 );
		add_action( 'manage_media_custom_column', array( $this, 'manage_media_custom_column' ), 10, 2 );
		add_action( 'admin_head', array( $this, 'admin_head' ), 10, 2 );
		add_action( 'plugins_loaded', array( $this, 'plugins_loaded' ) );
		add_action( 'init', array( $this, 'init' ) );
		add_action( 'profile_update', array( $this, 'profile_update' ) );
	}

	public function get_version() {
		return WPLR_SYNC_VERSION;
	}

	public function get_error() {
		if ( $this->error )
			return $this->error;
		else
			return __( 'Unknown error.', 'wplr-sync' );
	}

	/*****************************************************************************
		WP GALLERY: FOLDERS, COLLECTIONS AND KEYWORDS
	*****************************************************************************/

	// function foogallery_shortcode( $atts ) {
	// 	$ids = $this->gallery_images( array(), $atts );
	// 	if ( !empty( $ids ) && count( $ids ) > 0 ) {
	// 		$atts['ids'] = $ids;
	// 	}
	// 	return $atts;
	// }
	
	function collection_images_shortcode( $result, $defaults, $atts ) {
		$thumnails = $this->collection_images( array(), $atts );

		$result['wplr-thumbnails'] = $thumnails;
		return $result;
	}

	/**
	 * We receive an id from $atts['wplr-folder']
	 * from which we get all the collections, we ignore sub-folders
	 * for each collection we return the first image, the collection id and name
	 */
	function collection_images( $ids, $atts ){
		$ids = empty( $ids ) ? array() : $ids;
		$inner_folders = array();

		if ( !array_key_exists( 'wplr-folder', $atts ) ) { return $ids; }

		$folder = $atts['wplr-folder'];
		$collections = array();

		

		if ( !empty( $folder ) ) {
			$folder_collections = $this->get_collections_from_folder( $folder );
			foreach ( $folder_collections as $collection ) {
				$collections[] = $this->create_collection_array( $collection );
			}

			if ( array_key_exists( 'wplr-recursive', $atts ) &&  $atts['wplr-recursive'] == 'true' ) {
				$inner_folders = $this->get_folders_from_folder( $folder );
				foreach ( $inner_folders as $inner_folder ) {
					$inner_folder_collections = $this->get_collections_from_folder( $inner_folder );
					foreach ( $inner_folder_collections as $collection ) {
						$collections[] = $this->create_collection_array( $collection );
					}
				}
			}
		}

		return $collections;
	}

	private function create_collection_array( $collection ) {
		$std_collection = $this->get_collection( $collection );
		return array(
			'id' => $std_collection->wp_col_id,
			'collection' => $std_collection,
			'thumbnail' => $std_collection->featured_id,
		);
	}

	function gallery_images_shortcode( $result, $defaults, $atts ) {
		$ids = $this->gallery_images( array(), $atts );
		if ( !empty( $ids ) && count( $ids ) > 0 ) {
			$result['include'] = $ids;
			$result['id'] = null;
			$result['order'] = '';
			$result['orderby'] = 'post__in';
			foreach ( $atts as $key => $value ) {
				$result[$key] = $value;
			}
		}
		return $result;
	}

	function gallery_images( $ids, $attrs ) {
		$ids = empty( $ids ) ? array() : $ids;
		$addedIds = array();

		if ( !empty( $attrs['wplr-folder'] ) ) {
			$newIds = $this->get_collections_from_folder( $attrs['wplr-folder'] );
			$attrs['wplr-collection'] = implode( ',', $newIds );
		}
		if ( !empty( $attrs['wplr-collection'] ) ) {
			$collections = explode( ',', $attrs['wplr-collection'] );
			foreach ( $collections as $collection ) {
				$newIds = $this->get_media_from_collection( $collection );
				$addedIds = array_merge( $addedIds, $newIds );
			}
		}
		if ( !empty( $attrs['wplr-collections'] ) ) {
			$collections = explode( ',', $attrs['wplr-collections'] );
			foreach ( $collections as $collection ) {
				$newIds = $this->get_media_from_collection( $collection );
				$addedIds = array_merge( $addedIds, $newIds );
			}
		}
		if ( !empty( $attrs['wplr-keyword'] ) ) {
			$keywords = explode( ',', $attrs['wplr-keyword'] );
			foreach ( $keywords as $keyword ) {
				$newIds = $this->get_media_from_tag( $keyword );
				$addedIds = array_merge( $addedIds, $newIds );
			}
		}
		// Keywords outer join
		if ( !empty( $attrs['wplr-keywords'] ) ) {
			$keywords = explode( ',', $attrs['wplr-keywords'] );
			foreach ( $keywords as $keyword ) {
				$newIds = $this->get_media_from_tag( $keyword );
				$addedIds = array_merge( $addedIds, $newIds );
			}
		}
		// Keywords inner join
		if ( !empty( $attrs['wplr-keywords-and'] ) ) {
			$keywords = explode( ',', $attrs['wplr-keywords-and'] );
			foreach ( $keywords as $keyword ) {
				$newIds = $this->get_media_from_tag( $keyword );
				$addedIds = array_merge( $addedIds, $newIds );
			}
			$unique = array_unique( $addedIds );
			$diffkeys = array_diff_key( $addedIds, $unique );
			$addedIds = array_unique( $diffkeys );
		}
		return empty( $addedIds ) ? $ids : $addedIds;
	}

	/*****************************************************************************
		INIT
	*****************************************************************************/

	function init() {
		if ( get_option( 'wplr_enable_keywords', false ) || get_option( 'wplr_sync_keywords', false ) ) {
			new Meow_WPLR_Sync_Keywords();
		}
		if ( get_option( 'wr2x_big_image_size_threshold', false ) ) {
			add_filter( 'big_image_size_threshold', array( $this, 'big_image_size_threshold' ) );
		}

		// $res = $this->get_collection(5);
		// print_r($res);
		// exit;
	}

	function big_image_size_threshold() {
		return false;
	}

	function plugins_loaded() {
		// Part of the core, settings and stuff
		$this->admin = new Meow_WPLR_Sync_Admin();
		if ( is_admin() ) {
			global $wplr_admin;
			$wplr_admin = $this->admin;
			new Meow_WPLR_Sync_UI( $this );
		}

		// APIs
		new Meow_WPLR_Sync_API();
		if ( get_option( "wplr_public_api", true ) ) {
			new Meow_WPLR_Sync_Public_API();
		}

		// Rest
		if ( $this->is_rest ) {
			new Meow_WPLR_Sync_Rest( $this, $this->admin );
		}

		$loaded = load_plugin_textdomain( 'wplr-sync', false, dirname( plugin_basename( __FILE__ ) ) . '/languages/' );
		$plugins = get_option( 'wplr_plugins' );
		if ( is_array( $plugins ) ) {
			$dir = trailingslashit( plugin_dir_path( __FILE__ ) ) . trailingslashit( 'extensions' );
			$valid = array();
			$isdead = false;
			foreach ( $plugins as $plugin ) {
				if ( file_exists( trailingslashit( $dir ) . $plugin ) ) {
					include( trailingslashit( $dir ) . $plugin  );
					array_push( $valid, $plugin );
				}
				else {
					$plugin = preg_replace( '/([0-9]_)(\w+)/i', '$2', $plugin );
					if ( file_exists( trailingslashit( $dir ) . $plugin ) ) {
						include( trailingslashit( $dir ) . $plugin  );
						array_push( $valid, $plugin );
					}
					$isdead = true;
				}
			}
			if ( $isdead ) {
				update_option( 'wplr_plugins', $valid );
			}
		}
	}

	/*
		CORE
	*/

	function log( $data, $force = false ) {
		if ( !$force && !get_option( 'wplr_debuglogs', false ) )
			return;
		try {
			if ( is_writable( dirname( __FILE__ ) ) ) {
				$fh = fopen( trailingslashit( dirname( __FILE__ ) ) . 'wplr-sync.log', 'a' );
				if ( ! $fh ) {
					throw new Exception( 'Cannot open log file.' );
				}
				$date = date( "Y-m-d H:i:s" );
				fwrite( $fh, "$date: {$data}\n" );
				fclose( $fh );
			}
			else {
				error_log( 'Cannot create or write the Photo Engine Logs.' );
			}
		}
		catch ( Exception $e ) {
			error_log( 'Cannot create or write the Photo Engine Logs: ' . $e->getMessage() );
		}
	}

	function profile_update( $user_id ) {
		$token = get_user_meta( $user_id, 'wplr_auth_token', true );
		if ( empty( $token ) ) {
			$token = $this->generate_auth_token( $user_id );
		}
	}

	/**
	 * Generates a new auth token for the specified user and stores it in DB
	 * @param WP_User $user
	 * @return string The new token
	 */
	function generate_auth_token( $userId ) {
		static $MIN_LENGTH = 24;
		static $MAX_LENGTH = 32;

		// Seed
		list( $usec, $sec ) = explode( ' ', microtime() );
		$seed = $sec + $usec * 1000000;
		srand( $seed );

		// Compose
		$r = '';
		$chars = str_split( '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ' );
		$nChars = count( $chars );
		$length = rand( $MIN_LENGTH, $MAX_LENGTH );
		for ( $i = 0; $i < $length; $i++ ) $r .= $chars[rand( 0, $nChars - 1 )];

		// Save
		if ( update_user_meta( $userId, 'wplr_auth_token', $r ) === false ) {
			throw new Exception( "Save Failure" );
		}

		return $r;
	}

	function check_db() {
		$this->log( '[WP/LR] Checking the database...' );

		global $wpdb;
		$tbl_s = $wpdb->prefix . 'lrsync';
		$tbl_m = $wpdb->prefix . 'lrsync_meta';
		$tbl_c = $wpdb->prefix . 'lrsync_collections';
		$tbl_r = $wpdb->prefix . 'lrsync_relations';
	
		$messages = array();
	
		// To make sure there are primary keys (Added in version 6.0+)
		$messages[] = 'Checking '. $tbl_s . ' table...';
		if ( !$wpdb->get_var( $wpdb->prepare( "SELECT COUNT(1) 
			FROM information_schema.table_constraints 
			WHERE table_schema = '%s'
			AND table_name = '%s' 
			AND constraint_name = 'PRIMARY';", $wpdb->dbname, $tbl_s ) ) ) {
			meow_wplrsync_activate();

			$messages[] = '🟠 Primary key added to ' . $tbl_s;
		} else {
			$messages[] = '🟢 Primary key exists in ' . $tbl_s;
		}
		

		// Check if the table $tbl_m exists (Added in version 6.0+)
		$messages[] = 'Checking '. $tbl_m . ' table...';
		if ( !$wpdb->get_var( $wpdb->prepare( "SELECT COUNT(1) FROM information_schema.tables WHERE table_schema = '%s' AND table_name = '%s';", $wpdb->dbname, $tbl_m ) ) ) {
			meow_wplrsync_activate();

			$messages[] = '🟠 Table ' . $tbl_m . ' created.';
		} else {
			$messages[] = '🟢 Table ' . $tbl_m . ' exists.';
		}
	
		// Check if the table $tbl_r exists
		$messages[] = 'Checking '. $tbl_r . ' table...';
		if ( !$wpdb->get_var( $wpdb->prepare( "SELECT COUNT(1) FROM information_schema.tables WHERE table_schema = '%s' AND table_name = '%s';", $wpdb->dbname, $tbl_r ) ) ) {
			meow_wplrsync_activate();

			$messages[] = '🟠 Table ' . $tbl_r . ' created.';
		} else {
			$messages[] = '🟢 Table ' . $tbl_r . ' exists.';
		}

		// Check if the table $tbl_c exists (Added in version 6.0+)
		$messages[] = 'Checking '. $tbl_c . ' table...';
		if ( !$wpdb->get_var( $wpdb->prepare( "SELECT COUNT(1) FROM information_schema.tables WHERE table_schema = '%s' AND table_name = '%s';", $wpdb->dbname, $tbl_c ) ) ) {
			meow_wplrsync_activate();

			$messages[] = '🟠 Table ' . $tbl_c . ' created.';
		} else {
			$messages[] = '🟢 Table ' . $tbl_c . ' exists.';
		}
	
		// Check if the new column 'source' exists in collections table (Added in version 6.0+)
		$messages[] = 'Checking column source in ' . $tbl_c . ' table...';
		if ( !$wpdb->get_var( $wpdb->prepare( "SELECT COUNT(1) FROM information_schema.columns WHERE table_schema = '%s' AND table_name = '%s' AND column_name = '%s';", $wpdb->dbname, $tbl_c, 'source' ) ) ) {
			meow_wplrsync_activate();

			$messages[] = '🟠 Column source added to ' . $tbl_c;
		} else {
			$messages[] = '🟢 Column source exists in ' . $tbl_c;
		}
	
		// Check if the new column 'featured_id' exists in collections table (Added in version 6.0+)
		$messages[] = 'Checking column featured_id in ' . $tbl_c . ' table...';
		if ( !$wpdb->get_var( $wpdb->prepare( "SELECT COUNT(1) FROM information_schema.columns WHERE table_schema = '%s' AND table_name = '%s' AND column_name = '%s';", $wpdb->dbname, $tbl_c, 'featured_id' ) ) ) {
			meow_wplrsync_activate();

			$messages[] = '🟠 Column featured_id added to ' . $tbl_c;
		} else {
			$messages[] = '🟢 Column featured_id exists in ' . $tbl_c;
		}
	
		// Check if the new column 'slug' exists in collections table (Added in version 6.0+)
		// Create the slugs if they aren't there.
		$messages[] = 'Checking column slug in ' . $tbl_c . ' table...';
		if ( !$wpdb->get_var( $wpdb->prepare( "SELECT COUNT(1) FROM information_schema.columns WHERE table_schema = '%s' AND table_name = '%s' AND column_name = '%s';", $wpdb->dbname, $tbl_c, 'slug' ) ) ) {
			meow_wplrsync_activate();

			$messages[] = '🟠 Column slug added to ' . $tbl_c;

			$galleries = $wpdb->get_results( "SELECT wp_col_id id, name FROM $tbl_c", OBJECT);
			foreach ( $galleries as $gallery ) {
				$slug = sanitize_title( $gallery->name );
				//error_log("{$gallery->id} => $slug");
				$wpdb->update( $tbl_c, array( 'slug' => $slug ), array( 'wp_col_id' => $gallery->id ), array( '%s' ), array( '%d' ) );

				$messages[] = "Slug $slug added to gallery {$gallery->id}";
			}
		} else {
			$messages[] = '🟢 Column slug exists in ' . $tbl_c;
		}

		return $messages;
	}

	function reset_db() {
		do_action( 'wplr_reset' );
		meow_wplrsync_uninstall();
		meow_wplrsync_activate();
	}

	function wpml_original_id( $wpid ) {
		if ( $this->wpml_media_is_installed() ) {
			global $sitepress;
			$language = $sitepress->get_default_language( $wpid );
			return icl_object_id( $wpid, 'attachment', true, $language );
		}
		return $wpid;
	}

	function wpml_media_is_installed() {
		return defined( 'WPML_MEDIA_VERSION' );
		//return function_exists( 'icl_object_id' ) && !class_exists( 'Polylang' );
	}

	function wpml_original_array( $wpids ) {
		if ( $this->wpml_media_is_installed() ) {
			for ($c = 0; $c < count( $wpids ); $c++ ) {
				$wpids[$c] = $this->wpml_original_id( $wpids[$c] );
			}
			$wpids = array_unique( $wpids );
		}
		return $wpids;
	}

	function get_tags_from_media( $mediaId ) {
		global $wpdb;
		$tbl_meta = $wpdb->prefix . "lrsync_meta";
		$results = $wpdb->get_col( $wpdb->prepare( "
			SELECT value
			FROM $tbl_meta
			WHERE id = %d AND name = 'media_tag'
		", $mediaId ) );
		return $results;
	}

	function get_media_from_tag( $id ) {
		global $wpdb;
		$tbl_meta = $wpdb->prefix . "lrsync_meta";
		$results = $wpdb->get_col( $wpdb->prepare( "
			SELECT id
			FROM $tbl_meta
			WHERE value = %d AND name = 'media_tag'
		", $id ) );
		return $results;
	}

	function get_media_from_collection( $id, $limit = 100000, $offset = 0 ) {
		global $wpdb;
		$tbl_relations = $wpdb->prefix . "lrsync_relations";
		$results = $wpdb->get_col( $wpdb->prepare( "
			SELECT wp_id
			FROM $tbl_relations, $wpdb->posts p
			WHERE wp_id = p.ID
			AND wp_col_id = %d
			ORDER BY sort, post_date ASC
			LIMIT %d OFFSET %d
		", $id, $limit, $offset ) );
		return $results;
	}

	function get_collection_from_slug( $slug ) {
		global $wpdb;
		$tbl_col = $wpdb->prefix . "lrsync_collections";
		$info = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $tbl_col WHERE slug = %s", $slug ), OBJECT );
		return $info;
	}

	function get_folder_from_slug( $slug ) {
		return $this->get_collection_from_slug( $slug );
	}

	function get_collection( $id, $col_id = null ) {
		global $wpdb;
		$tbl_col = $wpdb->prefix . "lrsync_collections";

		if ( !is_null( $col_id ) ) {
			$info = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $tbl_col c
				WHERE wp_col_id = %d 
				AND lr_col_id = %d", $id, $col_id ), 
				OBJECT 
			);
		}
		else {
			$info = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $tbl_col 
				WHERE wp_col_id = %d", $id ), 
				OBJECT
			);
		}
		return $info;
	}

	function get_folder( $id ) {
		return $this->get_collection( $id );
	}

	function get_collections_from_media( $mediaId ) {
		global $wpdb;
		$tbl_relations = $wpdb->prefix . "lrsync_relations";
		$results = $wpdb->get_col( $wpdb->prepare( "
			SELECT wp_col_id
			FROM $tbl_relations
			WHERE wp_id = %d AND wp_col_id >= 0
		", $mediaId ) );
		return $results;
	}

	function get_collections_from_folder( $folderId = NULL) {
		global $wpdb;
		$tbl_c = $wpdb->prefix . 'lrsync_collections';
		if ( !$folderId ) {
			$collections = $wpdb->get_col( "SELECT wp_col_id FROM $tbl_c
				WHERE wp_folder_id IS NULL AND is_folder = 0 ORDER BY name, lr_col_id" );
		}
		else {
			$collections = $wpdb->get_col( $wpdb->prepare( "SELECT wp_col_id FROM $tbl_c
				WHERE wp_folder_id = %d AND is_folder = 0 ORDER BY name, lr_col_id", $folderId ) );
		}
		return $collections;
	}

	function get_folders_from_folder( $folderId = NULL) {
		global $wpdb;
		$tbl_c = $wpdb->prefix . 'lrsync_collections';
		if ( !$folderId ) {
			$collections = $wpdb->get_col( "SELECT wp_col_id FROM $tbl_c
				WHERE wp_folder_id IS NULL AND is_folder = 1 ORDER BY name, lr_col_id" );
		}
		else {
			$collections = $wpdb->get_col( $wpdb->prepare( "SELECT wp_col_id FROM $tbl_c
				WHERE wp_folder_id = %d AND is_folder = 1 ORDER BY name, lr_col_id", $folderId ) );
		}
		return $collections;
	}

	/**
	 * Returns MIME-type for a file
	 * @param string $file File path
	 * @return string
	 */
	function get_mime_type( $file ) {
		static $types;

		if ( function_exists( 'mime_content_type' ) ) {
			if ( $r = mime_content_type( $file ) ) {
				return $r; // Detect from content
			}
		}

		// Determine from extension
		if ( !$types ) {
			$types = array (
				'avi'     => 'video/x-msvideo',
				'bmp'     => 'image/bmp',
				'gif'     => 'image/gif',
				'ico'     => 'image/x-icon',
				'jpe'     => 'image/jpeg',
				'jpeg'    => 'image/jpeg',
				'jpg'     => 'image/jpeg',
				'avif'    => 'image/avif',
				'mov'     => 'video/quicktime',
				'movie'   => 'video/x-sgi-movie',
				'mp2'     => 'audio/mpeg',
				'mp3'     => 'audio/mpeg',
				'mpe'     => 'video/mpeg',
				'mpeg'    => 'video/mpeg',
				'mpg'     => 'video/mpeg',
				'png'     => 'image/png',
				'pnm'     => 'image/x-portable-anymap',
				'ppm'     => 'image/x-portable-pixmap',
				'qt'      => 'video/quicktime',
				'ras'     => 'image/x-cmu-raster',
				'rgb'     => 'image/x-rgb',
				'svg'     => 'image/svg+xml',
				'svgz'    => 'image/svg+xml',
				'tif'     => 'image/tiff',
				'tiff'    => 'image/tiff',
				'wbmp'    => 'image/vnd.wap.wbmp',
				'xbm'     => 'image/x-xbitmap',
				'xpm'     => 'image/x-xpixmap',
				'xwd'     => 'image/x-xwindowdump'
			);
		}
		$ext = pathinfo( $file, PATHINFO_EXTENSION );
		if ( !isset( $types[$ext] ) ) {
			error_log('Photo Engine could not find the mime type for the file (so it was set to jpg).');
			return 'image/jpeg';
		}
		return $types[$ext];
	}

	function read_collections_recursively( $parent = null, $results = array(), $isRemoval = false, $level = 0 ) {

		if ( $parent === null && !empty( $this->cached_collections ) ) {
			return $this->cached_collections;
		}

		global $wpdb;
		$tbl_c = $wpdb->prefix . 'lrsync_collections';
		if ( is_null( $parent ) )
			$collections = $wpdb->get_results( "SELECT wp_col_id, name, wp_folder_id, is_folder, source
				FROM $tbl_c WHERE wp_folder_id IS NULL ORDER BY is_folder DESC, name, lr_col_id", ARRAY_A );
		else
			$collections = $wpdb->get_results( $wpdb->prepare( "SELECT wp_col_id, name, wp_folder_id, is_folder, source
				FROM $tbl_c WHERE wp_folder_id = %d ORDER BY is_folder DESC, name, lr_col_id", $parent ), ARRAY_A );
		foreach ( $collections as $c ) {
			array_push( $results, array_merge(
				array(
					'level' => $level,
					'action' => $isRemoval ? 'remove_collection' : 'add_collection',
				), $c ) );
			if ( $c['is_folder'] )
				$results = $this->read_collections_recursively( $c['wp_col_id'], $results, $isRemoval, $level + 1 );
		}
		if ( $parent === null ) {
			$this->cached_collections = $results;
		}
		return $results;
	}

	function get_meta_from_value( $name, $value, $isArray = false ) {
		global $wpdb;
		$tbl_meta = $wpdb->prefix . "lrsync_meta";
		$results = $wpdb->get_col( $wpdb->prepare( "SELECT id FROM $tbl_meta WHERE name = %s AND value = %s", $name, $value ) );
		if ( count( $results ) > 1 )
			return $results;
		else if ( count( $results ) == 1 )
			return $isArray ? array( $results[0] ) : $results[0];
		return $isArray ? array() : null;
	}

	function get_meta( $name, $id, $isArray = false ) {
		global $wpdb;
		$tbl_meta = $wpdb->prefix . "lrsync_meta";
		$results = $wpdb->get_col( $wpdb->prepare( "SELECT value FROM $tbl_meta WHERE name = %s AND id = %d", $name, $id ) );
		if ( count( $results ) > 1 )
			return $results;
		else if ( count( $results ) == 1 )
			return $isArray ? array( $results[0] ) : $results[0];
		return $isArray ? array() : null;
	}

	function set_meta( $name, $id, $value, $unique = false ) {
		global $wpdb;
		$tbl_meta = $wpdb->prefix . "lrsync_meta";
		if ( $unique ) {
			$count = $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $tbl_meta WHERE name = %s AND id = %d", $name, $id ) );
			if ( $count > 0 ) {
				$wpdb->update( $tbl_meta, array( 'value' => $value ), array( 'name' => $name, 'id' => $id ), array( '%s' ), array( '%s', '%d' ) );
				return true;
			}
		}
		$wpdb->insert( $tbl_meta, array( 'name' => $name, 'id' => $id, 'value' => $value ) );
	}

	// If no value given, all meta for this id will be deleted
	function delete_meta( $name, $id, $value = null ) {
		global $wpdb;
		$tbl_meta = $wpdb->prefix . "lrsync_meta";
		if ( is_null( $value ) )
			$wpdb->query( $wpdb->prepare( "DELETE FROM $tbl_meta WHERE name = %s AND id = %d", $name, $id ) );
		else
			$wpdb->query( $wpdb->prepare( "DELETE FROM $tbl_meta WHERE name = %s AND id = %d AND value = %s", $name, $id, $value ) );
	}

	// Return SyncInfo for this WP ID
	function get_sync_info( $wpid ) {
		$wpid = $this->wpml_original_id( $wpid );
		global $wpdb;
		$table_name = $wpdb->prefix . "lrsync";
		$info = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $table_name WHERE wp_id = %d", $wpid ), OBJECT );
		return $info;
	}

	function get_sync_info_from_lr_id( $lr_id ) {
		global $wpdb;
		$table_name = $wpdb->prefix . "lrsync";
		$info = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $table_name WHERE lr_id = %d", $lr_id ), OBJECT );
		return $info;
	}

	// Check if there's a format mismatch between file extension and actual content
	function check_format_mismatch( $wp_id ) {
		// Check if this media is managed by WP/LR Sync
		$sync_info = $this->get_sync_info( $wp_id );
		if ( !$sync_info ) {
			return false;
		}

		// Get the file path and extension
		$file_path = get_attached_file( $wp_id );
		if ( !$file_path || !file_exists( $file_path ) ) {
			return false;
		}

		$file_extension = strtolower( pathinfo( $file_path, PATHINFO_EXTENSION ) );
		
		// Get the actual MIME type from file content
		$finfo = finfo_open( FILEINFO_MIME_TYPE );
		$actual_mime = finfo_file( $finfo, $file_path );
		finfo_close( $finfo );

		// Map MIME types to expected extensions
		$mime_to_ext = array(
			'image/jpeg' => array( 'jpg', 'jpeg' ),
			'image/png' => array( 'png' ),
			'image/avif' => array( 'avif' ),
			'image/tiff' => array( 'tiff', 'tif' ),
			'image/webp' => array( 'webp' ),
			'image/heic' => array( 'heic' ),
			'image/heif' => array( 'heif' )
		);

		// Check if there's a mismatch
		$has_mismatch = false;
		$expected_format = '';
		$actual_format = '';

		if ( isset( $mime_to_ext[$actual_mime] ) ) {
			$expected_extensions = $mime_to_ext[$actual_mime];
			if ( !in_array( $file_extension, $expected_extensions ) ) {
				$has_mismatch = true;
				$actual_format = $expected_extensions[0];
				$expected_format = $file_extension;
			}
		}

		return array(
			'has_mismatch' => $has_mismatch,
			'file_extension' => $file_extension,
			'actual_format' => $actual_format,
			'actual_mime' => $actual_mime,
			'message' => $has_mismatch ? 
				"This file has a .$file_extension extension but contains $actual_format data. This can happen when you change export formats in Lightroom. The file will display correctly, but the mismatched extension may cause confusion." : ''
		);
	}

	function get_hierarchy( $parent = null, $level = 0, $source = null ) {
		global $wpdb;
		$tbl_r = $wpdb->prefix . 'lrsync_relations';
		$tbl_c = $wpdb->prefix . 'lrsync_collections';

		$where_source = $source !== null ? $wpdb->prepare( "AND source = %s", $source ) : '';

		$current = array();

		if ( is_null( $parent ) ) {
			$collections = $wpdb->get_results( "SELECT *
				FROM $tbl_c 
				WHERE wp_folder_id IS NULL $where_source
				ORDER BY is_folder DESC, name, lr_col_id", OBJECT
			);
		}
		else {
			$collections = $wpdb->get_results( $wpdb->prepare( "SELECT *
				FROM $tbl_c 
				WHERE wp_folder_id = %d $where_source
				ORDER BY is_folder DESC, name, lr_col_id", $parent ), OBJECT
			);
		}

		foreach ( $collections as $c ) {
			$photos_count = 0;
			if ( !$c->is_folder ) {
				$photos_count = $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*)
					FROM $tbl_r 
					WHERE wp_col_id = %d", $c->wp_col_id )
				);
			}
			$current[] = array(
				'id' => $c->wp_col_id,
				'source' => $c->source,
				'level' => $level,
				'type' => $c->is_folder ? 'folder' : 'collection',
				'name' => $c->name,
				'slug' => $c->slug,
				'count' => $photos_count,
				'featured_id' => $c->featured_id,
				'children' => $c->is_folder ? $this->get_hierarchy( $c->wp_col_id, $level + 1 ) : null
			);
		}
		return $current;
	}

	function get_keywords_hierarchy( $parent = null, $level = 0 ) {
		global $wpdb;
		$tbl_m = $wpdb->prefix . 'lrsync_meta';

		$current = array();

		if ( is_null( $parent ) )
			$collections = $wpdb->get_results( "SELECT meta_id,
				MAX(IF(`name` = 'tag_name', id, NULL)) id,
				MAX(IF(`name` = 'tag_name', value, NULL)) name,
				MAX(IF(`name` = 'tag_parent', value, NULL)) parent
				FROM $tbl_m
				WHERE name = 'tag_name' OR name = 'tag_parent'
				GROUP BY id
				HAVING parent IS NULL
				ORDER BY id", OBJECT );
		else {
			$collections = $wpdb->get_results( $wpdb->prepare( "SELECT meta_id,
				MAX(IF(`name` = 'tag_name', id, NULL)) id,
				MAX(IF(`name` = 'tag_name', value, NULL)) name,
				MAX(IF(`name` = 'tag_parent', value, NULL)) parent
				FROM $tbl_m
				WHERE name = 'tag_name' OR name = 'tag_parent'
				GROUP BY id
				HAVING parent = %d
				ORDER BY id", $parent  ), OBJECT );
		}
		foreach ( $collections as $c ) {
			$photos_count = null;
			$count = $wpdb->get_var( "SELECT COUNT(*) FROM $tbl_m WHERE name = 'media_tag' AND value = {$c->id}" );
			$current[] = array(
				'id' => $c->id,
				'level' => $level,
				'name' => $c->name,
				'count' => $count,
				'children' => !empty( $c->id ) ? $this->get_keywords_hierarchy( $c->id, $level + 1 ) : array()
			);
		}
		return $current;
	}

	function get_gallery( $id ) {
		global $wpdb;
		$tbl_r = $wpdb->prefix . 'lrsync_relations';
		$photos = $wpdb->get_results( $wpdb->prepare( "
			SELECT wp_id id
			FROM $tbl_r r
			WHERE wp_col_id = %d
			ORDER BY sort", $id ), ARRAY_A );
		foreach ( $photos as &$photo ) {
			$id = $photo['id'];
			$photo['title'] = get_the_title( $id );
			$photo['full_size'] = stripslashes( wp_get_attachment_url( $id ) );
			$photo['thumbnail'] = stripslashes( wp_get_attachment_thumb_url( $id, 'post-thumbnail' ) );
		}
		return $photos;
	}

	function delete_media( $lr_id, $wp_col_id = null ) {
		global $wpdb;
		$lrinfo = $this->get_sync_info_from_lr_id( $lr_id );

		if ( empty( $lrinfo ) ) {
			error_log( "Photo Engine: seems like this media doesn't exist or has been already removed ($lr_id)." );
			return true;
		}

		// Remove media from collection
		$this->remove_media_from_collection( $lrinfo->wp_id, $wp_col_id );

		// Delete media if it is not part of any collection
		$tbl_r = $wpdb->prefix . 'lrsync_relations';
		$left = $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $tbl_r WHERE wp_id = %d", $lrinfo->wp_id ) );
		if ( $left < 1 ) {
			// Delete the media, it is not used anywhere
			$table_name = $wpdb->prefix . "lrsync";
			$sync_files = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM $table_name WHERE lr_id = %d", $lr_id), OBJECT );
			$delete_count = 0;
			foreach ( $sync_files as $sync ) {
				if ( wp_delete_attachment( $sync->wp_id, true ) ) {
					$wpdb->query( $wpdb->prepare( "DELETE FROM $table_name WHERE lr_id = %d", $lr_id ) );
					$delete_count++;

					//TODO: DELETE KEYWORDS
					// Are the tags used by this Media now useless?
					$keywords = $this->get_meta( 'media_tag', $sync->wp_id, true );
					foreach ( $keywords as $keyword ) {
						$results = $this->get_meta_from_value( 'media_tag', $keyword, true );
						if ( count( $results ) < 1 ) {
							$this->delete_keyword( $keyword );
						}
					}

				}
			}
			if ( count( $sync_files ) < 1 ) {
				// There were no files to remove
				return true;
			}
			else if ( $delete_count > 0 ) {
				// Files were removed
				do_action( 'wplr_remove_media', (int)$lrinfo->wp_id );
				return true;
			}
			else {
				// Nothing was removed, strangely
				$this->error = __( "The attachment could not be removed.", 'wplr-sync' );
				return false;
			}
		}
		else {
			// Don't delete the media, it is used somewhere else
			return true;
		}
	}

	function delete_attachment( $wp_id ) {
		$wp_id = $this->wpml_original_id( $wp_id );
		$this->sync_media_tags( $wp_id );
		global $wpdb;
		$table_name = $wpdb->prefix . "lrsync";
		$sql = $wpdb->prepare( "DELETE FROM $table_name WHERE wp_id = %d", $wp_id );
		$wpdb->query( $sql );
		$table_name = $wpdb->prefix . "lrsync_relations";
		$sql = $wpdb->prepare( "DELETE FROM $table_name WHERE wp_id = %d", $wp_id );
		$wpdb->query( $sql );
	}

	function unlink_media( $lr_id, $wp_id ) {
		$wp_id = $this->wpml_original_id( $wp_id );
		global $wpdb;
		$table_name = $wpdb->prefix . "lrsync";

		// Remove media
		if ( $wp_id ) {
			$sync = $this->get_sync_info( $wp_id );
			if ( $sync ) {
				$wpdb->query( $wpdb->prepare( "DELETE FROM $table_name WHERE wp_id = %d", $sync->wp_id ) );
				return true;
			}
		}
		else {
			$wpdb->query( $wpdb->prepare( "DELETE FROM $table_name WHERE lr_id = %d", $lr_id ) );
			return true;
		}

		$this->error = __( "There is no link for this media.", 'wplr-sync' );
		return false;
	}

	function link_media( $lr_id, $wp_id ) {
		$wp_id = $this->wpml_original_id( $wp_id );
		global $wpdb;
		$table_name = $wpdb->prefix . "lrsync";
		if ( empty( $wp_id ) ) {
			$this->error = __( "The arguments lr_id and wp_id are required.", 'wplr-sync' );
			return false;
		}
		if ( !wp_attachment_is_image( $wp_id ) ) {
			$this->error = __( "Attachment " . ($wp_id ? $wp_id : "[null]") . " does not exist or is not an image.", 'wplr-sync' );
			return false;
		}
		$sync = $this->get_sync_info( $wp_id );
		if ( !$sync ) {
			$wpdb->insert( $table_name,
				array(
					'wp_id' => $wp_id,
					'lr_id' => $lr_id,
					'lr_file' => null,
					'lastsync' => null
				)
			);
		}
		else {
			$wpdb->query( $wpdb->prepare( "UPDATE $table_name
				SET lr_id = %d
				WHERE wp_id = %d", $lr_id, $wp_id )
			);
		}
		$sync = $this->get_sync_info( $wp_id );
		$info = Meow_WPLR_Sync_LRInfo::fromRow( $sync );
		return $info;
	}

	function list_sync_media() {
		global $wpdb;
		$table_name = $wpdb->prefix . "lrsync";
		$sync_files = $wpdb->get_results( "SELECT * FROM $table_name WHERE lr_id >= 0 AND wp_id >= 0", OBJECT );
		$list = array();
		foreach ( $sync_files as $sync_file ) {
			$info = Meow_WPLR_Sync_LRInfo::fromRow( $sync_file );
			array_push( $list, $info );
		}
		return $list;
	}

	function update_metadata( $wp_id, $lrinfo, $isTranslation = false ) {
		// Update Title, Description and Caption

		$meta = null;
		if ( $isTranslation ) {
			$meta = get_post( $wp_id, ARRAY_A );
		}

		// Update Title, Caption and Desc (if needed)
		if ( $lrinfo->sync_title || $lrinfo->sync_caption || $lrinfo->sync_desc ) {
			$post = array( 'ID' => $wp_id );
			if ( $lrinfo->sync_title && ( !$meta || empty( $meta['post_title'] ) ) )
				$post['post_title'] = $lrinfo->lr_title;
			if ( $lrinfo->sync_desc && ( !$meta || empty( $meta['post_content'] ) ) )
				$post['post_content'] = $lrinfo->lr_desc;
			if ( $lrinfo->sync_caption && ( !$meta || empty( $meta['post_excerpt'] ) ) )
				$post['post_excerpt'] = $lrinfo->lr_caption;
			wp_update_post( $post );
		}

		// Update Alt Text if needed
		if ( $lrinfo->sync_alt_text ) {
			if ( $isTranslation )
				$meta_alt = get_post_meta( $wp_id, '_wp_attachment_image_alt', true );
			if ( !$isTranslation || empty( $meta_alt ) )
				update_post_meta( $wp_id, '_wp_attachment_image_alt', $lrinfo->lr_alt_text );
		}
	}

	function create_keyword( $lrTagId, $name, $lrTagParentId = null ) {
		$this->set_meta( 'tag_name', $lrTagId, $name, true );
		$this->set_meta( 'tag_parent', $lrTagId, $lrTagParentId, true );
		do_action( 'wplr_add_tag', (int)$lrTagId, $name, $lrTagParentId );
	}

	function update_keyword( $lrTagId, $name ) {
		$this->set_meta( 'tag_name', $lrTagId, $name, true );
		do_action( 'wplr_update_tag', (int)$lrTagId, $name );
	}

	function move_keyword( $lrTagId, $lrTagParentId ) {
		$previous = $this->get_meta( 'tag_parent', $lrTagId );
		$this->set_meta( 'tag_parent', $lrTagId, $lrTagParentId, true );
		do_action( 'wplr_move_tag', (int)$lrTagId, $lrTagParentId, $previous );
	}

	function delete_keyword( $lrTagId ) {
		$this->delete_meta( 'tag_name', $lrTagId );
		$this->delete_meta( 'tag_parent', $lrTagId );
		do_action( 'wplr_remove_tag', (int)$lrTagId );
		$kids = $this->get_meta_from_value( 'tag_parent', $lrTagId, true );
		foreach ( $kids as $kid ) {
			$kidName = $this->get_meta( 'tag_name', $kid );
			$this->delete_meta( 'tag_parent', $kid );
			do_action( 'wplr_update_tag', (int)$kid, $kidName, null );
		}
		$media = $this->get_meta_from_value( 'media_tag', $lrTagId, true );
		foreach ( $media as $m ) {
			$this->delete_meta( 'media_tag', $m );
			do_action( 'wplr_remove_media_tag', (int)$m, $lrTagId );
		}
	}


	function flatten_tags( $importTags, $allTags = array() ) {
		foreach ( $importTags as $tag ) {
			$currentTag = $tag;
			$allTags[(int)$tag['id']] = array(
				'id' => $tag['id'],
				'name' => trim( $tag['name'] ), // trim( $tag['name'], '\\"\' '),
				'parent' => null
			);
			while ( isset( $currentTag['parent'] ) && is_array( $currentTag['parent'] ) ) {
				$allTags[(int)$currentTag['id']]['parent'] = $currentTag['parent']['id'];
				$currentTag = $currentTag['parent'];
				$allTags[(int)$currentTag['id']] = array(
					'id' => $currentTag['id'],
					'name' => trim( $currentTag['name'] ), // trim( $currentTag['name'], '\\"\' '),
					'parent' => null
				);
			}
		}
		return $allTags;
	}

	function sync_media_tags( $wp_id, $tags = '' ) {
		// If tags is not an array (so maybe an old string of tags, or empty tag, let's set it to empty)
		if ( !is_array( $tags ) )
			$tags = array();
		$newTags = array();
		$flatten = $this->flatten_tags( $tags );
		$deathcount = 1666;

		// Read the tags given by LR, add them in the meta if they are new.
		while ( count( $flatten ) > 0 && $deathcount > 0  ) {
			$tag = array_shift( $flatten );

			$deathcount--;
			$pTagName = $this->get_meta( 'tag_name', $tag['id'] );
			$pTagParent = $this->get_meta( 'tag_parent', $tag['id'] );

			// Tag does not exist
			if ( empty( $pTagName ) ) {

				// Has no parent, we can create it
				if ( $tag['parent'] == null ) {
					$this->create_keyword( $tag['id'], $tag['name'] );
					array_push( $newTags, $tag['id'] );
					continue;
				}
				// Has a parent, which is already registered
				$parentName = $this->get_meta( 'tag_name', $tag['parent'] );
				if ( !empty( $parentName ) ) {
					$this->create_keyword( $tag['id'], $tag['name'], $tag['parent'] );
					array_push( $newTags, $tag['id'] );
					continue;
				}
			}

			// Tag exists
			if ( !empty( $pTagName ) ) {

				// But has different name, so we update it
				if ( $pTagName != $tag['name'] )
					$this->update_keyword( $tag['id'], $tag['name'] );

				// But has different parent
				if ( $pTagParent != (int)$tag['parent'] )
					$this->move_keyword( $tag['id'], (int)$tag['parent'] );

				array_push( $newTags, $tag['id'] );
				continue;
			}

			// Couldn't handle the tag, we put it back in
			array_push( $flatten, $tag );
		}

		// Take care of the tags for the media
		if ( !is_array( $newTags ) )
			$newTags = array();
		$oldTags = $this->get_meta( 'media_tag', $wp_id, true );
		if ( !is_array( $oldTags ) )
			$oldTags = array();
		$toAdds = array_diff( $newTags, $oldTags );
		foreach ( $toAdds as $toAdd ) {
			$this->set_meta( 'media_tag', $wp_id, $toAdd );
			do_action( 'wplr_add_media_tag', (int)$wp_id, trim( $toAdd ) );
		}
		$toDeletes = array_diff( $oldTags, $newTags );
		if ( count( $toDeletes ) > 0 ) {
			foreach ( $toDeletes as $toDelete ) {
				$this->delete_meta( 'media_tag', $wp_id, $toDelete );
				do_action( 'wplr_remove_media_tag', (int)$wp_id, trim( $toDelete ) );

				// Is the tag now useless?
				$results = $this->get_meta_from_value( 'media_tag', $toDelete, true );
				if ( count( $results ) < 1 ) {
					$this->delete_keyword( $toDelete );
				}
			}
		}
		return true;
	}

	function get_exif_datetime( $path, $format = 'Y-m-d H:i:s' ) {
		if( empty( $path ) || !file_exists( $path ) ) {
			$this->log( "The file $path does not exist." );
			return null;
		}

		if ( !function_exists( 'exif_read_data' ) ) {
			$this->log( "The EXIF library for PHP is not enabled." );
			return null;
		}
		$exif_data = null;
		try {
			$exif_data = @exif_read_data( $path );
		}
		catch ( Exception $e ) {
			$exif_data = null;
			error_log( $e->getMessage() );
		}
		if ( !empty( $exif_data ) && !empty( $exif_data[ 'DateTimeOriginal' ] ) ) {
			$takentime = strtotime( $exif_data[ 'DateTimeOriginal' ] );
			$takentime = date( $format, $takentime );
			return $takentime;
		}
		$this->log( "Couldn't read the EXIF DateTimeOriginal for $path." );
		return null;
	}

	//If user prefers to use the time of the image instead of "now" in Media Library
	function update_media_date( $wp_id ) {
		if ( get_option( 'wplr_use_taken_date', false ) ) {
			$path = get_attached_file( $wp_id );
			$takentime = $this->get_exif_datetime( $path );
			if ( $takentime ) {
				$media = array(
					'ID' => $wp_id,
					'post_date' => $takentime,
					'post_date_gmt' => $takentime,
				);
				wp_update_post( $media );
			}
		}
	}

	// This allows third-party plugins or scripts to check the existence of the files in a 
	// different way, for instance, on a remote server.
	function check_file_exists( $file ) {
		$exists = apply_filters( 'wplr_file_exists', null, $file );
		if ( $exists === null )
			$exists = file_exists( $file );
		return $exists;
	}

	function sync_media_update( $lrinfo, $tmp_path, $sync ) {
		global $wpdb;
		$table_name = $wpdb->prefix . "lrsync";
		$wp_id = $sync->wp_id;
		$meta = wp_get_attachment_metadata( $wp_id );
		$current_file = get_attached_file( $wp_id );
		$isSameFile = false;

		// Check if the new file is the same as the one already uploaded
		if ( $this->check_file_exists( $current_file ) && get_option( 'wplr_check_same_file', false ) ) {
			clearstatcache();
			$old_size = get_transient( 'wplr-media-size-' . $wp_id );
			$new_size = filesize( $tmp_path );
			$isSameFile = strval( $old_size ) === strval( $new_size );
			//error_log("IS SAME FILE ? ${old_size} === ${new_size} -> " . ($isSameFile ? 'true' : 'false'));
		}

		// If the file is different (or not existent), let's replace it
		if ( !$isSameFile ) {

			// Support for WP Retina 2x
			if ( function_exists( 'wr2x_generate_images' ) )
				wr2x_delete_attachment( $wp_id );

			// The file doesn't exist anymore for some reason
			if ( !$this->check_file_exists( $current_file ) ) {
				error_log( "Photo Engine: get_attached_file() returned empty. Assuming broken DB, delete link and continue." );
				$this->delete_attachment( $wp_id );
			}

			$pathinfo = pathinfo( $current_file );
			if ( !isset( $pathinfo['dirname'] ) ) {
				error_log( "Photo Engine: pathinfo() failed in sync_media_update with " . $current_file );
				$this->error = __( "Could not handle the file on the server-side.", 'wplr-sync' );
				return false;
			}
			$basepath = $pathinfo['dirname'];

			// Let's clean everything first
			if ( wp_attachment_is_image( $wp_id ) ) {
				$sizes = $this->get_image_sizes();
				foreach ($sizes as $name => $attr) {
					if (isset($meta['sizes'][$name]) && isset($meta['sizes'][$name]['file']) && file_exists( trailingslashit( $basepath ) . $meta['sizes'][$name]['file'] )) {
						$normal_file = trailingslashit( $basepath ) . $meta['sizes'][$name]['file'];
						$pathinfo = pathinfo( $normal_file );

						// Support for WP Retina 2x
						if ( function_exists( 'wr2x_generate_images' ) )
							$retina_file = trailingslashit( $pathinfo['dirname'] ) . $pathinfo['filename'] . wr2x_retina_extension() . $pathinfo['extension'];

						// Test if the file exists and if it is actually a file (and not a dir)
						// Some old WordPress Media Library are sometimes broken and link to directories
						if ( file_exists( $normal_file ) && is_file( $normal_file ) )
							unlink( $normal_file );

						// Support for WP Retina 2x
						if ( function_exists( 'wr2x_generate_images' ) && ( file_exists( $retina_file ) && is_file( $retina_file ) ) )
								unlink( $retina_file );
					}
				}
			}
			if ( file_exists( $current_file ) )
				unlink( $current_file );

			// Insert the new file and delete the temporary one
			copy( $tmp_path, $current_file );
			chmod( $current_file, 0644 );
		}

		// Update the Upload/TakenTime Date
		$this->update_media_date( $wp_id );

		// Update metadata
		$this->update_metadata( $wp_id, $lrinfo );

		// If there are translations, maybe they need to be updated too!
		// Udate 2017/08/28: No, it's better to only keep the main media translated.
		// if ( $this->wpml_media_is_installed() ) {
		// 	global $sitepress;
		// 	$trid = $sitepress->get_element_trid( $wp_id, 'post_attachment' );
		// 	$translations = $sitepress->get_element_translations( $trid, 'post_attachment' );
		// 	foreach( $translations as $k => $v ) {
		// 		if ( $v->element_id != $wp_id )
		// 			$this->update_metadata( $v->element_id, $lrinfo, true );
		// 	}
		// }
		
		if ( !$isSameFile ) {

			// Generate the images
			require_once( ABSPATH . 'wp-admin/includes/image.php' );
			$metadata = null;
			
			try {
				$metadata = wp_generate_attachment_metadata( $wp_id, $current_file );
			}
			catch ( Exception $e ) {
				$this->error = __( "Could not generate attachment metadata for " . $current_file . " ( ID: " . $wp_id . " ). Error: " . $e->getMessage(), 'wplr-sync' );
				return false;
			}
			
			wp_update_attachment_metadata( $wp_id, $metadata );

			// Support for WP Retina 2x
			if ( function_exists( 'wr2x_generate_images' ) )
				wr2x_generate_images( wp_get_attachment_metadata( $wp_id ) );

			if ( get_option( 'wplr_check_same_file', false ) ) {
				set_transient( 'wplr-media-size-' . $wp_id, filesize( $current_file ) );
			}
		}

		$wpdb->query( $wpdb->prepare( "UPDATE $table_name
			SET lr_file = %s, lastsync = NOW()
			WHERE lr_id = %d", $lrinfo->lr_file, $lrinfo->lr_id )
		);

		if ( !empty( $lrinfo->tags ) )
			$this->sync_media_tags( $wp_id, $lrinfo->tags );

		$tbl_r = $wpdb->prefix . "lrsync_relations";
		$gallery_ids = $wpdb->get_col( $wpdb->prepare( "SELECT wp_col_id FROM $tbl_r WHERE wp_id = %d", $wp_id ) );

		// Increase the version number
		$this->increase_media_version( (int)$wp_id );

		do_action( 'wplr_update_media', (int)$wp_id, $gallery_ids );
		return true;
	}

	function increase_media_version( $mediaId ) {
		$version = get_post_meta( $mediaId, '_media_version', true );
		$version = $version ? intval( $version ) + 1 : 2;
		update_post_meta( $mediaId, '_media_version', $version );
		return $version;
	}

	function wplr_sanitize_filename( $filename ) {
		if ( get_option( 'wplr_filename_accents', false ) )
			return $filename;
		$path = pathinfo( $filename );
		$new = preg_replace( '/.' . $path['extension'] . '$/', '', $filename );
		return sanitize_title( $new ) . '.' . $path['extension'];
	}

	function sync_media_add( $lrinfo, $tmp_path, $userId = null ) {
		global $wpdb;
		$tbl_wplr = $wpdb->prefix . "lrsync";
		$upload_dir = wp_upload_dir();
		
		if ( get_option( 'wplr_use_taken_date', false ) ) {
			if ( get_option( 'wplr_upload_folder', 'taken_date' ) === 'taken_date' ) {
				$date = $this->get_exif_datetime( $tmp_path, 'Y/m' );
				if ( $date ) {
					$upload_dir = wp_upload_dir( $date );
				}
			}
		}
		$newfile = wp_unique_filename( $upload_dir["path"], $this->wplr_sanitize_filename( $lrinfo->lr_file ) );
		$newpath = trailingslashit( $upload_dir["path"] ) . $newfile;
		chmod( $tmp_path, 0644 );
		if ( !@move_uploaded_file( $tmp_path, $newpath ) ) {
			$this->error = __( "Could not copy the file.", 'wplr-sync' );
			return false;
		}
		if ( empty( $userId ) )
			$userId = get_current_user_id();
		$wp_upload_dir = wp_upload_dir();
		if ( !$wp_id = wp_insert_attachment( array(
			'guid' => $wp_upload_dir['url'] . '/' . basename( $newpath ),
			'post_title' => $lrinfo->lr_title,
			'post_author' => $userId,
			'post_content' => $lrinfo->lr_desc,
			'post_excerpt' => $lrinfo->lr_caption,
			'post_mime_type' => $this->get_mime_type( $newpath ),
			'post_status' => "inherit",
		), $newpath ) ) {
			$this->error = __( "Could not insert attachment for " . $newpath, 'wplr-sync' );
			return false;
		}

		// Create Alt Text
		update_post_meta( $wp_id, '_wp_attachment_image_alt', $lrinfo->lr_alt_text );

		require_once( ABSPATH . 'wp-admin/includes/image.php' );
		$attach_data = wp_generate_attachment_metadata( $wp_id, $newpath );
		wp_update_attachment_metadata( $wp_id, $attach_data );

		// Support for WP Retina 2x
		if ( function_exists( 'wr2x_generate_images' ) ) {
			wr2x_generate_images( $attach_data );
		}

		$wpdb->insert( $tbl_wplr,
			array(
				'wp_id' => $wp_id,
				'lr_id' => ( $lrinfo->lr_id == "" || $lrinfo->lr_id == null ) ? -1 : $lrinfo->lr_id,
				'lr_file' => $lrinfo->lr_file,
				'lastsync' => current_time( 'mysql' )
			)
		);

		// Update the Upload/TakenTime Date
		$this->update_media_date( $wp_id );

		if ( get_option( 'wplr_check_same_file', false ) ) {
			set_transient( 'wplr-media-size-' . $wp_id, filesize( $newpath ) );
		}

		do_action( 'wplr_add_media', (int)$wp_id );

		if ( !empty( $lrinfo->tags ) )
			$this->sync_media_tags( $wp_id, $lrinfo->tags );

		return true;
	}

	function sync_media( $lrinfo, $tmp_path, $wp_col_id = null, $user_id = null ) {
		require_once( ABSPATH . 'wp-admin/includes/media.php' );
		do_action( 'wplr_presync_media', $lrinfo, $tmp_path );

		global $wpdb;
		$table_name = $wpdb->prefix . "lrsync";
		$sync_files = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM $table_name WHERE lr_id = %d", $lrinfo->lr_id ), OBJECT );

		if ( $tmp_path == null || empty( $tmp_path ) ) {
			$this->error = __( "The file was not uploaded.", 'wplr-sync' );
			return false;
		}

		// Never synced, create the attachment
		if ( !$sync_files ) {
			if ( !$this->sync_media_add( $lrinfo, $tmp_path, $user_id ) )
				return false;
		}

		// Synced info found in DB, go through them
		else {
			$updates = 0;
			foreach ( $sync_files as $sync ) {
				if ( $this->sync_media_update( $lrinfo, $tmp_path, $sync ) )
					$updates++;
			}
			// In case DB is broken and no updates was made, we need to create the attachment
			if ( $updates == 0 ) {
				if ( !$this->sync_media_add( $lrinfo, $tmp_path, $user_id ) )
					return false;
			}
		}
		if ( file_exists( $tmp_path ) )
			unlink( $tmp_path );

		// Returns only one result even if there are many.
		$sync = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $table_name WHERE lr_id = %d", $lrinfo->lr_id ), OBJECT );
		$info = Meow_WPLR_Sync_LRInfo::fromRow( $sync );
		if ( empty( $info ) ) {
			$this->error = __( "The information about the media could not be retrieved.", 'wplr-sync' );
			return false;
		}

		// Handle the collection if any
		if ( !is_null( $wp_col_id ) ) {
			$this->add_media_to_collection( $sync->wp_id, $wp_col_id );
		}

		do_action( 'wplr_sync_media', $sync );

		// Apply the order again, if needed.
		$this->apply_collection_order_by( $wp_col_id );

		return $info;
	}

	function get_image_sizes() {
		$sizes = array();
		global $_wp_additional_image_sizes;
		foreach (get_intermediate_image_sizes() as $s) {
			$crop = false;
			if (isset($_wp_additional_image_sizes[$s])) {
				$width = intval($_wp_additional_image_sizes[$s]['width']);
				$height = intval($_wp_additional_image_sizes[$s]['height']);
				$crop = $_wp_additional_image_sizes[$s]['crop'];
			} else {
				$width = get_option($s.'_size_w');
				$height = get_option($s.'_size_h');
				$crop = get_option($s.'_crop');
			}
			$sizes[$s] = array( 'width' => $width, 'height' => $height, 'crop' => $crop );
		}
		return $sizes;
	}

	function pHashImage( $path ) {
		$pHash = apply_filters( 'wplr_calculate_pHash', null, $path );
		if ( !empty( $pHash ) )
			return $pHash;
		try {
			require_once( WPLR_SYNC_PATH . '/vendor/phasher.class.php' );
			$I = PHasher::Instance();
			return $I->HashAsString( $I->HashImage( $path, 0, 0, 16 ), true );
		}
		catch ( Throwable $e ) {
			error_log( 'PHasher error: ' . $e->getMessage() );
			return null;
		}
	}

	// Returns link info for a file at this path
	function linkinfo_upload( $path, $meta = null, $thumbnailPath = null ) {
		$exif = null;
		if ( $meta == null) {
			require_once( ABSPATH . 'wp-admin/includes/image.php' );
			$meta = wp_read_image_metadata( $path );
			$exif = ( isset( $meta, $meta["created_timestamp"] ) && (int)$meta["created_timestamp"] > 0 ) ? date( "Y/m/d H:i:s", $meta["created_timestamp"] ) : null;
		}
		else if ( isset( $meta, $meta["image_meta"], $meta["image_meta"]["created_timestamp"] ) && (int)$meta["image_meta"]["created_timestamp"] > 0 ) {
			$exif = date( "Y/m/d H:i:s", $meta["image_meta"]["created_timestamp"] );
		}
		return array(
			'wp_phash' => $this->pHashImage( empty( $thumbnailPath ) ? $path : $thumbnailPath ),
			'wp_exif' => $exif
		);
	}

	// Returns link info to help LR to find the original image
	function linkinfo_media( $wp_id ) {
		$wp_id = $this->wpml_original_id( $wp_id );
		if ( !wp_attachment_is_image( $wp_id ) ) {
			$this->error = __( "Attachment " . ($wp_id ? $wp_id : "[null]") . " does not exist or is not an image.", 'wplr-sync' );
			return false;
		}
		$attached_file = get_attached_file( $wp_id );
		$metadata = wp_get_attachment_metadata( $wp_id );
		$attached_file_thumb = isset( $metadata['sizes']['large']['file'] ) ?
			str_replace( wp_basename( $attached_file ), $metadata['sizes']['large']['file'], $attached_file ) : null;
		if ( !file_exists( $attached_file_thumb ) ) {
			$attached_file_thumb = null;
		}
		$linkinfo = $this->linkinfo_upload( $attached_file, $metadata, $attached_file_thumb );
		return array(
			'wp_id' => $wp_id,
			'wp_url' => wp_get_attachment_url( $wp_id ),
			'wp_phash' => $linkinfo["wp_phash"],
			'wp_exif' => $linkinfo["wp_exif"]
		);
	}

	// Returns an array of wp_id linked to this lr_id
	function list_wpids( $lr_id ) {
		global $wpdb;
		$table_name = $wpdb->prefix . "lrsync";
		$wp_ids = $wpdb->get_results( $wpdb->prepare( "SELECT p.wp_id FROM $table_name p WHERE p.lr_id = %d", $lr_id ) );
		return $wp_ids;
	}

	function list_ignored() {
		global $wpdb;
		$table_name = $wpdb->prefix . "lrsync";
		$posts = $wpdb->get_results(
			"SELECT wp_id ID
			FROM $table_name
			WHERE lr_id = 0
			ORDER BY wp_id DESC", OBJECT );
		return $posts;
	}

	function list_duplicates() {
		global $wpdb;
		$table_name = $wpdb->prefix . "lrsync";
		$images = $wpdb->get_results(
			"SELECT lr.lr_id, lr.lr_file, GROUP_CONCAT(lr.wp_id SEPARATOR ',') as wpids
			FROM $wpdb->posts p, $table_name lr
			WHERE p.ID = lr.wp_id AND lr.lr_id != 0
			GROUP BY lr.lr_id
			HAVING COUNT(p.ID) > 1
			ORDER BY lr.lr_id DESC", OBJECT );
		return $images;
	}

	function list_unassigned( $allfields = false, $limit = null, $skip = null, $orderBy = null, $order = null) {
		global $wpdb;
		$table_name = $wpdb->prefix . "lrsync_relations";
		$potentials = array();

		$whereIsOriginal = "";
		if ( $this->wpml_media_is_installed() ) {
			global $sitepress;
			$tbl_wpml = $wpdb->prefix . "icl_translations";
			$language = $sitepress->get_default_language();
			$whereIsOriginal = "AND p.ID IN (SELECT element_id FROM $tbl_wpml WHERE element_type = 'post_attachment' AND language_code = '$language') ";
		}

		$limitClause = "";
		if ($limit !== null && $skip !== null) {
			$limitClause = $wpdb->prepare("LIMIT %d, %d", $skip, $limit);
		}

		$orderByClause = "ORDER BY p.ID DESC ";
		if ($orderBy !== null & $order !== null) {
			if ($orderBy === 'type') {
				$orderByClause = 'ORDER BY p.ID ' . ( $order === 'asc' ? 'ASC' : 'DESC' ) . ' ';
			}
		}

		if ( $allfields ) {
			$posts = $wpdb->get_results( "SELECT * FROM $wpdb->posts p
			WHERE post_status = 'inherit'
			AND post_mime_type <> ''
			AND p.ID NOT IN (SELECT wp_id FROM $table_name) " .
			$whereIsOriginal .
			$orderByClause .
			$limitClause );
		}
		else {
			$posts = $wpdb->get_col( "SELECT p.ID FROM $wpdb->posts p
			WHERE post_status = 'inherit'
			AND post_mime_type <> ''
			AND p.ID NOT IN (SELECT wp_id FROM $table_name) " .
			$whereIsOriginal .
			$orderByClause .
			$limitClause );
		}

		foreach ( $posts as $post ) {
			if ( $allfields ) {
				if ( !wp_attachment_is_image( $post->ID ) )
					continue;
				array_push( $potentials, $post );
			}
			else {
				if ( !wp_attachment_is_image( $post ) )
					continue;
				array_push( $potentials, $post );
			}
		}
		return $potentials;
	}

	function list_unlinks( $allfields = false ) {
		global $wpdb;
		$table_name = $wpdb->prefix . "lrsync";
		$potentials = array();

		$whereIsOriginal = "";
		if ( $this->wpml_media_is_installed() ) {
			global $sitepress;
			$tbl_wpml = $wpdb->prefix . "icl_translations";
			$language = $sitepress->get_default_language();
			$whereIsOriginal = "AND p.ID IN (SELECT element_id FROM $tbl_wpml WHERE element_type = 'post_attachment' AND language_code = '$language') ";
		}

		if ( $allfields ) {
			$posts = $wpdb->get_results( "SELECT * FROM $wpdb->posts p
			WHERE post_status = 'inherit'
			AND post_mime_type <> ''
			AND p.ID NOT IN (SELECT wp_id FROM $table_name) " .
			$whereIsOriginal .
			"ORDER BY p.ID DESC" );
		}
		else {
			$posts = $wpdb->get_col( "SELECT p.ID FROM $wpdb->posts p
			WHERE post_status = 'inherit'
			AND post_mime_type <> ''
			AND p.ID NOT IN (SELECT wp_id FROM $table_name) " .
			$whereIsOriginal .
			"ORDER BY p.ID DESC" );
		}

		foreach ( $posts as $post ) {
			if ( $allfields ) {
				if ( !wp_attachment_is_image( $post->ID ) )
					continue;
				array_push( $potentials, $post );
			}
			else {
				if ( !wp_attachment_is_image( $post ) )
					continue;
				array_push( $potentials, $post );
			}
		}
		return $potentials;
	}

	/*****************************************************************************
		COLLECTIONS
	*****************************************************************************/

	// Does collection contains Media ID
	function collection_contains( $wp_col_id, $wp_id ) {
		global $wpdb;
		$tbl_r = $wpdb->prefix . 'lrsync_relations';
		$count = $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) 
			FROM $tbl_r 
			WHERE wp_id = %d 
			AND wp_col_id = %d", 
			$wp_id, $wp_col_id ) 
		);
		return $count >= 1;
	}

	// Set the Featured Image for the given Collection or Folder ID.
	function set_featured_image( $collectionId, $featuredImageId ) {
		global $wpdb;
		$tbl_col = $wpdb->prefix . 'lrsync_collections';	
		$wpdb->query( $wpdb->prepare( "UPDATE $tbl_col 
			SET featured_id = %d WHERE wp_col_id = %d", $featuredImageId, $collectionId ) 
		);
	}

	function apply_featured_image_to_parents_folders( $col, $featured_id, $depth = 0 ) {
		if ( !empty( $col->wp_folder_id ) ) {
			$folder = $this->get_folder( $col->wp_folder_id );
			if ( empty( $folder->featured_id ) ) {
				$this->set_featured_image( $folder->wp_col_id, $featured_id );
			}
			if ( $depth < 10 ) {
				$this->apply_featured_image_to_parents_folders( $folder, $featured_id, $depth++ );
			}
		}
	}

	function add_media_to_collection( $wp_id, $wp_col_id, $sort = 0 ) {
		global $wpdb;
		$tbl_r = $wpdb->prefix . 'lrsync_relations';
		$tbl_col = $wpdb->prefix . 'lrsync_collections';	
		if ( !$this->collection_contains( $wp_col_id, $wp_id ) ) {

			$inserted = $wpdb->insert( $tbl_r,
				array( 'wp_col_id' => $wp_col_id, 'wp_id' => $wp_id, 'sort' => $sort ),
				array( '%d', '%d', '%s' )
			);

			if ( $inserted ) {
				// Manage the Featured Image ID automatically (if it is empty)
				$collection = $this->get_collection( $wp_col_id );
				$featured_id = empty( $collection->featured_id ) ? $wp_id : $collection->featured_id;
				$this->apply_featured_image_to_parents_folders( $collection, $featured_id );

				// Update the Featured Image
				$this->set_featured_image( $wp_col_id, $featured_id );

				// Update the Last Sync
				$wpdb->query( $wpdb->prepare( "UPDATE $tbl_col SET lastsync = %s 
					WHERE wp_col_id = %d", current_time( 'mysql' ), $wp_col_id ) 
				);

				if ( $wp_col_id > -1 )
					do_action( "wplr_add_media_to_collection", (int)$wp_id, (int)$wp_col_id );
			}
			else {
				$this->error = __( "Could not add media to collection.", 'wplr-sync' );
				return false;
			}
		}
	}

	function remove_media_from_collection( $wp_id, $wp_col_id ) {
		global $wpdb;
		$tbl_r = $wpdb->prefix . 'lrsync_relations';
		$tbl_col = $wpdb->prefix . 'lrsync_collections';
		if ( !is_null( $wp_col_id ) ) {
			$wpdb->query( $wpdb->prepare( "DELETE FROM $tbl_r WHERE wp_id = %d AND wp_col_id = %d", $wp_id, $wp_col_id ) );
			if ( $wp_col_id >= 0 ) {
				$wpdb->query( $wpdb->prepare( "UPDATE $tbl_col
					SET lastsync = %s
					WHERE wp_col_id = %d", current_time( 'mysql' ), $wp_col_id )
				);
				do_action( 'wplr_remove_media_from_collection', (int)$wp_id, (int)$wp_col_id );
			}
			return true;
		}
		return false;
	}

	function create_collection( $type = 'collection', $name = '', $parent_folder = null, $source = 'wp', $lr_col_id = null ) {
		global $wpdb;
		$tbl_col = $wpdb->prefix . 'lrsync_collections';
		$slug = $this->make_slug_unique( -1, sanitize_title( $name ) );

		// Create the collection or folder
		$success = $wpdb->insert( $tbl_col,
			array(
				'source' => $source,
				'lr_col_id' => $lr_col_id,
				'is_folder' => $type == 'folder' ? 1 : 0,
				'name' => htmlspecialchars( $name, ENT_QUOTES, 'UTF-8' ),
				'slug' => $slug,
				'lastsync' => current_time( 'mysql' )
			),
			array( '%s', '%d', '%d', '%s', '%s' )
		);

		// Set the parent for this collection or folder (if there is any)
		if ( $success ) {
			$wp_col_id = $wpdb->insert_id;
			if ( !is_null( $parent_folder ) ) {
				$wpdb->query( $wpdb->prepare( "UPDATE $tbl_col
					SET wp_folder_id = %s
					WHERE wp_col_id = %d", $parent_folder, $wp_col_id )
				);
			}
			do_action( "wplr_create_$type", (int)$wp_col_id, (int)$parent_folder, array( 'name' => $name ) );
			return $this->get_collection( $wp_col_id );
		}
		else {
			$this->error = __( "Could not create the folder or collection.", 'wplr-sync' );
			return false;
		}
	}

	function make_slug_unique( $col_id, $slug, $counter = null ) {
		global $wpdb;
		$slug = is_null( $counter ) ? $slug : ($slug . '-' . $counter);
		$tbl_col = $wpdb->prefix . 'lrsync_collections';
		$exists = $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $tbl_col
			WHERE wp_col_id <> %d 
			AND slug = %s", $col_id, $slug ) );
		if ( $exists ) {
			$counter = is_null( $counter ) ? 1 : $counter + 1;
			$slug = $this->make_slug_unique( $col_id, $slug, $counter );
		}
		return $slug;
	}

	function update_collection( $wp_col_id, $name = '', $slug = '' ) {
		global $wpdb;
		$tbl_col = $wpdb->prefix . 'lrsync_collections';
		$current = $this->get_collection( $wp_col_id );
		$type = $current->is_folder ? 'folder' : 'collection';
		$slug = $this->make_slug_unique( $wp_col_id, empty( $slug ) ? sanitize_title( $name ) : $slug );

		// If name is different, we update it
		if ( $name != $current->name ) {
			$wpdb->query( $wpdb->prepare( "UPDATE $tbl_col
				SET name = %s, slug = %s, lastsync = %s
				WHERE wp_col_id = %d", $name, $slug, current_time( 'mysql' ), $current->wp_col_id )
			);
			do_action( "wplr_update_$type" . ( $current->is_folder ? 'folder' : 'gallery' ), 
				(int)$current->wp_col_id, array( 'name' => $name ) );
		}
	}

	function move_collection( $wp_col_id, $parent_folder = null ) {
		global $wpdb;
		$tbl_col = $wpdb->prefix . 'lrsync_collections';
		$current = $this->get_collection( $wp_col_id );
		$type = $current->is_folder ? 'folder' : 'collection';

		// If parent folder is different, we update it
		if ( $parent_folder != $current->wp_folder_id ) {
			if ( is_null( $parent_folder ) )
				$wpdb->query( $wpdb->prepare( "UPDATE $tbl_col SET wp_folder_id = NULL WHERE wp_col_id = %d", $current->wp_col_id ) );
			else
				$wpdb->query( $wpdb->prepare( "UPDATE $tbl_col SET wp_folder_id = %d WHERE wp_col_id = %d", $parent_folder, $current->wp_col_id ) );
			do_action( "wplr_move_$type", (int)$current->wp_col_id, (int)$parent_folder, (int)$current->wp_folder_id );
		}
	}

	function collection_checks( $collection ) {
		if ( empty( $collection ) ) {
			$this->log("Empty collection found, skipping." );
			$this->error = __( "Collection is empty.", 'wplr-sync' );
			return false;
		}

		if ( empty( $collection->name ) ) {
			$this->log("Collection name is empty, skipping." );
			$this->error = __( "Collection name is empty.", 'wplr-sync' );
			return false;
		}

		if ( $collection->type != 'folder' && $collection->type != 'collection' ) {
			$this->log("Collection type is invalid, skipping." );
			$this->error = __( "Collection type is invalid.", 'wplr-sync' );
			return false;
		}

		return true;
	}

	function sync_collection( $collections, $source = 'lr' ) {
		global $wpdb;
		$folder = null;
		foreach ( $collections as &$collection ) {
			// Basic checks
			if ( !$this->collection_checks( $collection ) ) continue;


			$type = $collection->type == 'folder' ? 'folder' : 'collection';

			$parent_folder = null;
			if ( !empty( $folder ) && !empty( $folder->wp_col_id ) ) {
				$parent_folder = (int)$folder->wp_col_id;
			}

			// Get the collection if it already exists
			$row = empty( $collection->wp_col_id ) ? null : $this->get_collection( $collection->wp_col_id, $collection->lr_col_id );

			if ( empty( $row ) ) {
				// Collection needs to be created in DB.
				$collection = $this->create_collection( $type, $collection->name, $parent_folder, $source, $collection->lr_col_id );
			}
			else {
				// Collection exists in DB, check for changes.
				$collection->wp_col_id = $row->wp_col_id;
				// It's a bit stupid to call those two functions, we should clean then and call them
				// only when really needed.
				$this->update_collection( $collection->wp_col_id, $collection->name );
				$this->move_collection( $collection->wp_col_id, $parent_folder );
			}
			$folder = $collection;
		}
		return $collections;
	}

	private $maxdepth = 100;
	private $currentdepth = 0;

	function delete_collection_recursively( $tbl_col, $tbl_r, $tbl_lr, $wp_col_id ) {
		global $wpdb;
		if ( $this->currentdepth++ > $this->maxdepth ) {
			error_log( "Photo Engine: delete_collection_recursively() reached maxdepth." );
			return false;
		}
		$children = $wpdb->get_col( $wpdb->prepare( "SELECT DISTINCT(wp_col_id) FROM $tbl_col WHERE wp_folder_id = %d", $wp_col_id ) );
		foreach ( $children as $kid ) {
			$res = $this->delete_collection_recursively( $tbl_col, $tbl_r, $tbl_lr, $kid );
			if ( !$res )
				return false;
		}

		// For Lightroom!
		// Lists all the LR IDs linked to that collection.
		// So that doesn't count the images which were dropped in this collection without a LR ID.
		$lr_ids = $wpdb->get_col( $wpdb->prepare( "SELECT DISTINCT(lr_id) FROM $tbl_r r
			INNER JOIN $tbl_lr l ON r.wp_id = l.wp_id WHERE r.wp_col_id = %d", $wp_col_id ) );
		if ( !empty( $lr_ids ) ) {
			foreach ( $lr_ids as $lr_id ) {
				if ( !$this->delete_media( $lr_id, $wp_col_id ) ) {
					return false;
				}
			}
		}

		// For PhotoEngine!
		// List all the WP IDs left for this collection.
		$wp_ids = $wpdb->get_col( $wpdb->prepare( "SELECT DISTINCT(wp_id) FROM $tbl_r r
			WHERE r.wp_col_id = %d", $wp_col_id ) );
		if ( !empty( $wp_ids ) ) {
			foreach ( $wp_ids as $wp_id ) {
				if ( !$this->remove_media_from_collection( $wp_id, $wp_col_id ) ) {
					return false;
				}
			}
		}

		$collection = $wpdb->get_row( $wpdb->prepare( "SELECT wp_col_id, is_folder FROM $tbl_col
			WHERE wp_col_id = %d", $wp_col_id ), OBJECT, 0 );
		if ( !empty( $collection ) ) {
			$type = $collection->is_folder ? 'folder' : 'collection';
			do_action( "wplr_remove_{$type}", (int)$wp_col_id );
			$wpdb->query( $wpdb->prepare( "DELETE FROM $tbl_col WHERE wp_col_id = %d", $wp_col_id ) );
		}
		return true;
	}

	function delete_collection( $wp_col_id ) {
		global $wpdb;
		$folder = null;
		$tbl_col = $wpdb->prefix . 'lrsync_collections';
		$tbl_r = $wpdb->prefix . 'lrsync_relations';
		$tbl_lr = $wpdb->prefix . 'lrsync';
		$currentdepth = 0;
		$result = $this->delete_collection_recursively( $tbl_col, $tbl_r, $tbl_lr, $wp_col_id );
		return $result;
	}

	// Set the meta 'collection_order' for the collection
	// Values can be: 'date-asc', 'date-desc' or 'name'.
	// This value be used by other plugins to apply the order.
	function order_collection_by( $wp_col_id, $order = null ) {
		if ( empty( $wp_col_id ) )
			return true;
		if ( empty( $order ) )
			$this->delete_meta( 'collection_order', $wp_col_id );
		else {
			$this->set_meta( 'collection_order', $wp_col_id, $order, true );
			$this->apply_collection_order_by( $wp_col_id );
		}
		return true;
	}

	// In the case the meta 'collection_order' is set, Photo Engine can
	// re-organize the order of the images by calling this function.
	function apply_collection_order_by( $wp_col_id ) {
		global $wpdb;
		$orderBy = $this->get_meta( 'collection_order', $wp_col_id );
		$sqlOrderBy = '';
		if ( $orderBy === 'name-asc' )
			$sqlOrderBy = ' ORDER BY p.post_title ASC';
		else if ( $orderBy === 'date-asc' )
			$sqlOrderBy = ' ORDER BY p.post_date ASC';
		else if ( $orderBy === 'date-desc' )
			$sqlOrderBy = ' ORDER BY p.post_date DESC';

		if ( !empty( $sqlOrderBy ) ) {
			$tbl_r = $wpdb->prefix . 'lrsync';
			$wpIds = $this->get_media_from_collection( $wp_col_id );
			if ( !empty( $wpIds ) ) {
				$wpIdsPlaceHolders = array_fill( 0, count( $wpIds ), '%d' );
				$wpIdsPlaceHolders = implode( ', ', $wpIdsPlaceHolders );
				$query = $wpdb->prepare( "SELECT lr.lr_id
					FROM $wpdb->posts p
					INNER JOIN $tbl_r lr
					ON lr.wp_id = p.ID
					WHERE p.ID IN ($wpIdsPlaceHolders)" . $sqlOrderBy, $wpIds );
				$lrIds = $wpdb->get_col( $query );
				if ( !empty( $lrIds ) ) {
					$this->order_collection( $wp_col_id, $lrIds );
				}
			}
		}
	}

	function order_collection( $wp_col_id, $lr_ids ) {
		if ( empty( $wp_col_id ) )
			return true;
		global $wpdb;
		$tbl_r = $wpdb->prefix . 'lrsync_relations';
		$count = 0;
		$mediaIds = array();
		foreach ( $lr_ids as $lr_id ) {
			$info = $this->get_sync_info_from_lr_id( $lr_id );
			if ( !empty( $info ) ) {
				$wpdb->query( $wpdb->prepare( "UPDATE $tbl_r SET sort = %d WHERE wp_col_id = %d AND wp_id = %d",
					$count, $wp_col_id, $info->wp_id ) );
				array_push( $mediaIds, $info->wp_id );
			}
			else {
				error_log( "Could not find information for LR ID $lr_id while ordering the collection." );
			}
			$count++;
		}
		do_action( "wplr_order_collection", $mediaIds, (int)$wp_col_id );
		return true;
	}

	/*****************************************************************************
		USEFUL FUNCTIONS
	*****************************************************************************/

	function get_upload_root()
	{
		$uploads = wp_upload_dir();
		return $uploads['basedir'];
	}

	// Converts PHP INI size type (e.g. 24M) to int
	function parse_ini_size( $size ) {
		$unit = preg_replace('/[^bkmgtpezy]/i', '', $size);
		$size = preg_replace('/[^0-9\.]/', '', $size);
		if ( $unit )
			return round( $size * pow( 1024, stripos( 'bkmgtpezy', $unit[0] ) ) );
		else
			round( $size );
	}

	// This function should not work even with HVVM
	function b64_to_file( $str ) {

		// From version 1.3.4 (use uploads folder for tmp):
		if ( !file_exists( trailingslashit( $this->get_upload_root() ) . "wplr-tmp" ) )
			mkdir( trailingslashit( $this->get_upload_root() ) . "wplr-tmp" );
		$file = tempnam( trailingslashit( $this->get_upload_root() ) . "wplr-tmp", "wplr_" );

		// Before version 1.3.4:
		//$file = tempnam( sys_get_temp_dir(), "wplr" );

		$ifp = fopen( $file, "wb" );
		fwrite( $ifp, base64_decode( $str ) );
		fclose( $ifp );
		chmod( $file, 0664 );
		return $file;
	}

	/*****************************************************************************
		POST TYPE / COLLECTION RELATED COLUMN
	*****************************************************************************/

	function html_for_collection( $collection_id ) {
		$sync = $this->get_collection( $collection_id );
		$html = "";
		if ( !$sync ) {
			$html .= "<div>" . __( "Unknown", 'wplr-sync' ) . "</div>";
		}
		else {
			$name = $sync->name;
			$html .= "<div style='color: #006EFF;'>" . __( "Enabled", 'wplr-sync' ) . "</div>";
			if ( !strtotime( $sync->lastsync ) || $sync->lastsync == "0000-00-00 00:00:00" )
				$html .= "<div style='color: #0BF;'><small>" . __( "Never synced.", 'wplr-sync' ) . "</small></div>";
			else {
				if ( date('Ymd') == date('Ymd', strtotime( $sync->lastsync ) ) ) {
					$html .= "<div><small>" .
						sprintf( __( "Synced at %s with <i>$name</i>.", 'wplr-sync' ), date("g:ia", strtotime( $sync->lastsync ) ) ) .
						"</small></div>";
				}
				else {
					$html .= "<div><small>" .
						sprintf( __( "Synced at %s with <i>$name</i>.", 'wplr-sync' ), date("Y/m/d", strtotime( $sync->lastsync ) ) ) .
						"</small></div>";
				}
			}
			//$html .= "<div><small>LR COL ID: " . $sync->lr_col_id . "</small></div>";
		}
		return $html;
	}

	/*****************************************************************************
		MEDIA LIBRARY COLUMN
	*****************************************************************************/

	function html_for_media( $wpid, $sync = null ) {
		$wpid = $this->wpml_original_id($wpid);
		$html = "";
		if ( !$sync ) {
			$html .= "<div>" . __( "Unknown", 'wplr-sync' ) . "</div>";
			$html .= "<div>
			<small>LR ID:
				<input type='text' class='wplr-sync-lrid-input wplrsync-link-" . $wpid . "'></input>
				<span class='wplr-button' onclick='wplrsync_link($wpid)'>" . __( "Link", 'wplr-sync' ) . "</span>
			</small></div>";
		}
		else {
			if ( $sync->lr_id > 0 ) {
				$html .= "<div style='color: #006EFF;'>" . __( "Enabled", 'wplr-sync' ) . "</div>";

				if ( !strtotime( $sync->lastsync ) || $sync->lastsync == "0000-00-00 00:00:00" )
					$html .= "<div style='color: #0BF;'><small>" . __( "Never synced.", 'wplr-sync' ) . "</small></div>";
				else {
					if ( date('Ymd') == date('Ymd', strtotime( $sync->lastsync ) ) ) {
						$html .= "<div><small>" .
							sprintf( __( "Synced at %s", 'wplr-sync' ), date("g:ia", strtotime( $sync->lastsync ) ) ) .
							"</small></div>";
					}
					else {
						$html .= "<div><small>" .
							sprintf( __( "Synced at %s", 'wplr-sync' ), date("Y/m/d", strtotime( $sync->lastsync ) ) ) .
							"</small></div>";
					}
				}
				$html .= "<div><small>LR ID: " . $sync->lr_id . "</small></div>";
			}
			else if ( $sync->lr_id == 0 ) {
				$html .= "<div style='color: gray;'>" . __( "Ignored", 'wplr-sync' ) . "</div>";
			}
			$html .= "<small><span class='wplr-link-undo' onclick='wplrsync_unlink($sync->lr_id, $wpid)'>" .
				__( "(undo)", 'wplr-sync' ) .
				"</span></small>";
		}
		return $html;
	}

	function wplrsync_unlink() {
		$this->admin->wp_ajax_auth_check( 'wp_ajax_wplrsync_unlink' );
		$this->wplrsync_ajax_link_unlink(true);
	}

	function wplrsync_link() {
		$this->admin->wp_ajax_auth_check( 'wp_ajax_wplrsync_link' );
		$this->wplrsync_ajax_link_unlink();
	}

	function wplrsync_ajax_link_unlink( $is_unlink = false ) {
		if ( !current_user_can('upload_files') ) {
			echo json_encode( array( 'success' => false, 'message' => "You do not have the roles to perform this action." ) );
			die;
		}
		if ( !isset( $_POST['lr_id'] ) || $_POST['lr_id'] == "" || !isset( $_POST['wp_id'] ) || empty( $_POST['wp_id'] ) ) {
			echo json_encode( array( 'success' => false, 'message' => "Some information is missing." ) );
			die;
		}

		$lr_id = intval( $_POST['lr_id'] );
		$wp_id = $this->wpml_original_id( intval( $_POST['wp_id'] ) );

		$sync = null;
		if ( $is_unlink ) {

			if ( $this->unlink_media( $lr_id, $wp_id ) ) {
				echo json_encode( array(
					'success' => true,
					'html' => $this->html_for_media( $wp_id, null )
				) );
			}
			else {
				echo json_encode( array(
					'success' => false,
					'message' => $this->error || "Unknown error."
				) );
			}
		}
		else {
			$sync = $this->link_media( $lr_id, $wp_id );
			if ( $sync ) {
				echo json_encode( array(
					'success' => true,
					'html' => $this->html_for_media( $wp_id, $sync )
				) );
			}
			else {
				echo json_encode( array(
					'success' => false,
					'message' => $this->error || "Unknown error."
				) );
			}
		}
		die();
	}

	function admin_head() {
		echo '
			<style type="text/css">

				.wplr-button {
					background: #3E79BB;
					color: white;
					display: inline;
					padding: 2px 8px;
					text-transform: uppercase;
					margin-left: 1px;
					flex: 1;
					text-align: center;
				}

				.wplr-button:hover {
					cursor: pointer;
					background: #5D93CF;
				}

				.wplr-link-undo {
					color: #5E5E5E;
				}

				.wplr-link-undo:hover {
					cursor: pointer;
					color: #2ea2cc;
				}

				.wplr-sync-info {
					line-height: 14px;
				}

				.wplr-sync-lrid-input {
					width: 56px;
					font-size: 10px;
					font-weight: bold;
					color: black !important;
				}

			</style>

			<script>

				function wplrsync_handle_response( wp_id, response ) {
					reply = jQuery.parseJSON(response);
					if ( reply.success ) {
						// Remove box (if in WP/LR Dashboard)
						jQuery("#wplr-image-box-" + wp_id).remove();
						// Update row (if in Media Library)
						jQuery(".wplrsync-media-" + wp_id).html(reply.html);
					}
					else {
						alert(reply.message);
					}
				}

				function wplrsync_unlink( lr_id, wp_id ) {
					var data = { action: "wplrsync_unlink", lr_id: lr_id, wp_id: wp_id };
					jQuery.post(ajaxurl, data, function (response) {
						wplrsync_handle_response( wp_id, response );
					});
				}

				function wplrsync_link( wp_id, ignore ) {
					if (!ignore) {
						lr_id = jQuery(".wplrsync-link-" + wp_id).val();
					}
					else {
						lr_id = 0;
					}
					var data = { action: "wplrsync_link", lr_id: lr_id, wp_id: wp_id };
					jQuery.post(ajaxurl, data, function (response) {
						wplrsync_handle_response( wp_id, response );
					});
				}
			</script>
		';
	}

	function manage_media_columns( $cols ) {
		$cols["WPLRSync"] = "LR Sync";
		return $cols;
	}

	function manage_media_custom_column( $column_name, $wpid ) {
		if ( $column_name != 'WPLRSync' )
			return;
		$meta = wp_get_attachment_metadata( $wpid );
		if ( !($meta && isset( $meta['width'] ) && isset( $meta['height'] )) ) {
			return;
		}
		$info = $this->get_sync_info( $wpid );
		$lr_id = empty( $info ) ? null : $info->lr_id;
		$lastsync = empty( $info ) ? null : $info->lastsync;
		echo '<div class="wplr-sync-field" data-wp-id="' . $wpid . '" data-lr-id="' . 
			$lr_id . '" data-lastsync="' . $lastsync . '" data-is-server-side="true"></div>';
	}

	/*****************************************************************************
		HELPERS FOR TAXONOMIES MANAGEMENT
		USED BY KEYWORDS (CORE) AND POST TYPES (EXTENSION)
	*****************************************************************************/

	function create_taxonomy( $keywordId, $inKeywordId, $keyword, $taxonomy, $metaKey ) {
		global $wplr;

		$is_term_exists = false;

		$term = get_term_by( 'name', $keyword['name'], $taxonomy );
		if ( !empty( $term ) ) {
			$wplr->set_meta( $metaKey, $keywordId, $term->term_id, true );
			$is_term_exists = true;
		}

		// Create term
		if ( !$is_term_exists ) {
			$parentTermId = null;
			if ( !empty( $inKeywordId ) && is_taxonomy_hierarchical( $taxonomy ) )
				$parentTermId = $wplr->get_meta( $metaKey, $inKeywordId );
			$result = wp_insert_term( $keyword['name'], $taxonomy, $parentTermId ? array( 'parent' => $parentTermId ) : null );
			if ( is_wp_error( $result ) ) {
				error_log( "Issue while creating the keyword " . $keyword['name'] . "." );
				error_log( $result->get_error_message() );
				return;
			}
			$wplr->set_meta( $metaKey, $keywordId, $result['term_id'], true );
		}
	}

	function update_taxonomy( $folderId, $folder, $taxonomy, $metaKey ) {
		global $wplr;
		$termId = $wplr->get_meta( $metaKey, $folderId );
		wp_update_term( $termId, $taxonomy, array( 'name' => $folder['name'] ) );
	}

	// Move the folder (category) under another one.
	// If the folder is empty, then it is the root.
	function move_taxonomy( $folderId, $inFolderId, $taxonomy, $metaKey ) {
		global $wplr;
		$termId = $wplr->get_meta( $metaKey, $folderId );
		$parentTermId = null;
		if ( !empty( $inFolderId ) )
			$parentTermId = $wplr->get_meta( $metaKey, $inFolderId );
		wp_update_term( $termId, $taxonomy, array( 'parent' => $parentTermId ) );
	}

	function remove_taxonomy( $folderId, $taxonomy, $postType, $metaKey ) {
		global $wplr;
		$id = $wplr->get_meta( $metaKey, $folderId );
		$objs = get_objects_in_term( $id, $taxonomy );
		$args = array(
			'post_type' => $postType,
			'tax_query' => array(
				array( 'taxonomy' => $taxonomy, 'field' => 'id', 'terms' => (int)$id )
			)
		);
		$query = new WP_Query( $args );
		if ( $query->found_posts < 1 ) {
			$r = wp_delete_term( $id, $taxonomy );
			if ( is_wp_error( $r ) ) {
				error_log( "Issue while deleting the folder " . $folderId . "." );
				error_log( $r->get_error_message() );
				return;
			}
			$wplr->delete_meta( $metaKey, $folderId );
		}
	}

	// If postMetaKey is null, then we consider the postId is the ID
	// of the post type already (good for Media in Keywords)
	function add_taxonomy_to_posttype( $folderId, $collectionId, $taxonomy, $postMetaKey, $termMetaKey ) {
		global $wplr;
		$term = $this->get_term_from_folder( $folderId, $taxonomy, $termMetaKey );
		if ( !empty( $term ) ) {
			$postId = empty( $postMetaKey ) ? $collectionId : $wplr->get_meta( $postMetaKey, $collectionId );
			if ( empty( $postId ) ) {
				error_log( "Cannot find the post for $collectionId (postMetaKey: $postMetaKey)." );
				return;
			}
			$terms = wp_get_post_terms( $postId, $taxonomy, array( 'fields' => 'ids' ) );
			$terms[] = $term->term_id;
			$r = wp_set_post_terms( $postId, $terms, $taxonomy );
			if ( is_wp_error( $r ) )
				error_log( $r->get_error_message() );
		}
		else {
			error_log( "Could not add taxonomy $folderId to posttype $collectionId (taxonomy: $taxonomy, pm: $postMetaKey, tm: $termMetaKey)." );
		}
	}

	// If postMetaKey is null, then we consider the postId is the ID
	// of the post type already (good for Media in Keywords)
	function remove_taxonomy_from_posttype( $folderId, $collectionId, $taxonomy, $postMetaKey, $termMetaKey ) {
		global $wplr;
		if ( empty( $folderId ) )
			return;
		$postId = empty( $postMetaKey ) ? $collectionId : $wplr->get_meta( $postMetaKey, $collectionId );
		if ( empty( $postId ) ) {
			error_log( "Cannot find the post for $collectionId (postMetaKey: $postMetaKey)." );
			return;
		}
		$folderId = empty( $folderId ) ? null : $wplr->get_meta( $termMetaKey, $folderId );
		if ( empty( $folderId ) ) {
			//error_log( "Cannot find the related term for folder $folderId." );
			return;
		}
		$r = wp_remove_object_terms( (int)$postId, (int)$folderId, $taxonomy );
		if ( is_wp_error( $r ) )
			error_log( $r->get_error_message() );
	}

	function get_term_from_folder( $folderId, $taxonomy, $termMetaKey ) {
		global $wplr;
		if ( empty( $folderId ) )
			return;
		$parentTermId = $wplr->get_meta( $termMetaKey, $folderId );
		if ( empty( $parentTermId ) ) {
			error_log( "Cannot find the term for $folderId." );
			return;
		}
		$term = get_term_by( 'term_id', $parentTermId, $taxonomy );
		if ( empty( $term ) ) {
			error_log( "Cannot find information for the term $parentTermId (folder: $folderId, termMetaKey: $termMetaKey, taxonomy: $taxonomy)." );
			return;
		}
		return $term;
	}

	/**
	 *
	 * Roles & Access Rights
	 *
	 */
	public function can_access_settings() {
		return apply_filters( 'wplr_allow_setup', current_user_can( 'manage_options' ) );
	}

	public function can_access_features() {
		return apply_filters( 'wplr_allow_usage', current_user_can( 'upload_files' ) );
	}

}

?>
