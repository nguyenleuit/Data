<?php

class Meow_WPLR_Sync_Rest
{
	private $core = null;
	private $admin = null;
	private $namespace = 'wplr-sync/v1';

	public function __construct( $core, $admin ) {
		if ( !current_user_can( 'upload_files' ) ) {
			return;
		} 
		$this->core = $core;
		$this->admin = $admin;
		add_action( 'rest_api_init', array( $this, 'rest_api_init' ) );
	}

	function rest_api_init() {
		try {
			// SETTINGS
			register_rest_route( $this->namespace, '/update_option', array(
				'methods' => 'POST',
				'permission_callback' => array( $this->core, 'can_access_settings' ),
				'callback' => array( $this, 'rest_update_option' )
			) );
			register_rest_route( $this->namespace, '/all_settings', array(
				'methods' => 'GET',
				'permission_callback' => array( $this->core, 'can_access_settings' ),
				'callback' => array( $this, 'rest_all_settings' ),
			) );
			register_rest_route( $this->namespace, '/entries', array(
				'methods' => 'GET',
				'permission_callback' => array( $this->core, 'can_access_settings' ),
				'callback' => array( $this, 'rest_entries' ),
				'args' => array(
					'show' => array( 'required' => true, 'default' => 'unlinked' ),
				)
			) );
			register_rest_route( $this->namespace, '/wp_hierarchy', array(
				'methods' => 'GET',
				'permission_callback' => array( $this->core, 'can_access_features' ),
				'callback' => array( $this, 'rest_wp_hierarchy' ),
			) );
			register_rest_route( $this->namespace, '/lr_hierarchy', array(
				'methods' => 'GET',
				'permission_callback' => array( $this->core, 'can_access_features' ),
				'callback' => array( $this, 'rest_lr_hierarchy' ),
			) );
			register_rest_route( $this->namespace, '/all_media', array(
				'methods' => 'GET',
				'permission_callback' => array( $this->core, 'can_access_features' ),
				'callback' => array( $this, 'rest_all_media' ),
				'args' => array(
					'limit' => array( 'required' => false, 'default' => 20 ),
					'skip' => array( 'required' => false, 'default' => 0 ),
					'orderBy' => array( 'required' => false, 'default' => 'id' ),
					'order' => array( 'required' => false, 'default' => 'desc' ),
				)
			) );
			register_rest_route( $this->namespace, '/unassigned_entries', array(
				'methods' => 'GET',
				'permission_callback' => array( $this->core, 'can_access_features' ),
				'callback' => array( $this, 'rest_unassigned_entries' ),
				'args' => array(
					'limit' => array( 'required' => false, 'default' => 20 ),
					'skip' => array( 'required' => false, 'default' => 0 ),
					'orderBy' => array( 'required' => false, 'default' => 'id' ),
					'order' => array( 'required' => false, 'default' => 'desc' ),
				)
			) );
			register_rest_route( $this->namespace, '/folder_content', array(
				'methods' => 'POST',
				'permission_callback' => array( $this->core, 'can_access_features' ),
				'callback' => array( $this, 'rest_folder_content' ),
			) );
			register_rest_route( $this->namespace, '/gallery_content', array(
				'methods' => 'GET',
				'permission_callback' => array( $this->core, 'can_access_features' ),
				'callback' => array( $this, 'rest_gallery_content' ),
				'args' => array(
					'collectionId' => array( 'required' => false, 'default' => null ),
					'limit' => array( 'required' => false, 'default' => 20 ),
					'skip' => array( 'required' => false, 'default' => 0 ),
					'orderBy' => array( 'required' => false, 'default' => 'id' ),
					'order' => array( 'required' => false, 'default' => 'desc' ),
				)
			) );
			register_rest_route( $this->namespace, '/delete_hierarchy', array(
				'methods' => 'POST',
				'permission_callback' => array( $this->core, 'can_access_settings' ),
				'callback' => array( $this, 'rest_delete_hierarchy' ),
			) );
			register_rest_route( $this->namespace, '/keywords_hierarchy', array(
				'methods' => 'GET',
				'permission_callback' => array( $this->core, 'can_access_settings' ),
				'callback' => array( $this, 'rest_keywords_hierarchy' ),
			) );
			register_rest_route( $this->namespace, '/delete_keywords_hierarchy', array(
				'methods' => 'POST',
				'permission_callback' => array( $this->core, 'can_access_settings' ),
				'callback' => array( $this, 'rest_delete_keywords_hierarchy' ),
			) );

			register_rest_route( $this->namespace, '/sync_info', array(
				'methods' => 'POST',
				'permission_callback' => array( $this->core, 'can_access_features' ),
				'callback' => array( $this, 'rest_sync_info' )
			) );
			register_rest_route( $this->namespace, '/link', array(
				'methods' => 'POST',
				'permission_callback' => array( $this->core, 'can_access_features' ),
				'callback' => array( $this, 'rest_link' )
			) );
			register_rest_route( $this->namespace, '/unlink', array(
				'methods' => 'POST',
				'permission_callback' => array( $this->core, 'can_access_features' ),
				'callback' => array( $this, 'rest_unlink' )
			) );
			register_rest_route( $this->namespace, '/extensions_query', array(
				'methods' => 'POST',
				'permission_callback' => array( $this->core, 'can_access_features' ),
				'callback' => array( $this, 'rest_extensions_query' )
			) );
			register_rest_route( $this->namespace, '/extensions_init', array(
				'methods' => 'POST',
				'permission_callback' => array( $this->core, 'can_access_features' ),
				'callback' => array( $this, 'rest_extensions_init' )
			) );
			register_rest_route( $this->namespace, '/extensions_reset', array(
				'methods' => 'POST',
				'permission_callback' => array( $this->core, 'can_access_features' ),
				'callback' => array( $this, 'rest_extensions_reset' )
			) );
			register_rest_route( $this->namespace, '/clean', array(
				'methods' => 'POST',
				'permission_callback' => array( $this->core, 'can_access_features' ),
				'callback' => array( $this, 'rest_clean' )
			) );
			register_rest_route( $this->namespace, '/repair', array(
				'methods' => 'POST',
				'permission_callback' => array( $this->core, 'can_access_features' ),
				'callback' => array( $this, 'rest_repair' )
			) );
			register_rest_route( $this->namespace, '/create_folder', array(
				'methods' => 'POST',
				'permission_callback' => array( $this->core, 'can_access_features' ),
				'callback' => array( $this, 'rest_create_folder' )
			) );
			register_rest_route( $this->namespace, '/create_gallery', array(
				'methods' => 'POST',
				'permission_callback' => array( $this->core, 'can_access_features' ),
				'callback' => array( $this, 'rest_create_gallery' )
			) );
			register_rest_route( $this->namespace, '/update_folder', array(
				'methods' => 'POST',
				'permission_callback' => array( $this->core, 'can_access_features' ),
				'callback' => array( $this, 'rest_update_folder' )
			) );
			register_rest_route( $this->namespace, '/update_gallery', array(
				'methods' => 'POST',
				'permission_callback' => array( $this->core, 'can_access_features' ),
				'callback' => array( $this, 'rest_update_gallery' )
			) );
			register_rest_route( $this->namespace, '/delete_folder', array(
				'methods' => 'POST',
				'permission_callback' => array( $this->core, 'can_access_features' ),
				'callback' => array( $this, 'rest_delete_collection' )
			) );
			register_rest_route( $this->namespace, '/delete_gallery', array(
				'methods' => 'POST',
				'permission_callback' => array( $this->core, 'can_access_features' ),
				'callback' => array( $this, 'rest_delete_collection' )
			) );
			register_rest_route( $this->namespace, '/move_collection', array(
				'methods' => 'POST',
				'permission_callback' => array( $this->core, 'can_access_features' ),
				'callback' => array( $this, 'rest_move_collection' )
			) );
			register_rest_route( $this->namespace, '/move_media', array(
				'methods' => 'POST',
				'permission_callback' => array( $this->core, 'can_access_features' ),
				'callback' => array( $this, 'rest_move_media' )
			) );
			register_rest_route( $this->namespace, '/copy_media', array(
				'methods' => 'POST',
				'permission_callback' => array( $this->core, 'can_access_features' ),
				'callback' => array( $this, 'rest_copy_media' )
			) );
			register_rest_route( $this->namespace, '/remove_media', array(
				'methods' => 'POST',
				'permission_callback' => array( $this->core, 'can_access_features' ),
				'callback' => array( $this, 'rest_remove_media' )
			) );
			register_rest_route( $this->namespace, '/update_media', array(
				'methods' => 'POST',
				'permission_callback' => array( $this->core, 'can_access_features' ),
				'callback' => array( $this, 'rest_update_media' )
			) );
			register_rest_route( $this->namespace, '/update_featured_image', array(
				'methods' => 'POST',
				'permission_callback' => array( $this->core, 'can_access_features' ),
				'callback' => array( $this, 'rest_update_featured_image' )
			) );
		}
		catch (Exception $e) {
			var_dump($e);
		}
	}

	function rest_all_settings() {
		return new WP_REST_Response( [
			'success' => true,
			'data' => $this->admin->get_all_options()
		], 200 );
	}

	function rest_wp_hierarchy() {
		$hierarchy = $this->core->get_hierarchy(null, 0, 'wp');
		$hierarchy = $this->format_hierarchy( $hierarchy );
		return new WP_REST_Response( [
			'success' => true,
			'data' => $hierarchy
		], 200 );
	}

	function rest_lr_hierarchy() {
		$hierarchy = $this->core->get_hierarchy(null, 0, 'lr');
		$hierarchy = $this->format_hierarchy( $hierarchy );
		return new WP_REST_Response( [
			'success' => true,
			'data' => $hierarchy
		], 200 );
	}

	function rest_all_media($request) {
		$limit = sanitize_text_field( $request->get_param('limit') );
		$skip = sanitize_text_field( $request->get_param('skip') );
		$orderBy = sanitize_text_field( $request->get_param('orderBy') );
		$order = sanitize_text_field( $request->get_param('order') );
		global $wpdb;
		$total = (int)$wpdb->get_var( "SELECT COUNT(ID) FROM $wpdb->posts p 
			WHERE post_type='attachment' AND post_status='inherit'"
		);
		$orderSql = 'ORDER BY p.ID DESC ';
		if ($orderBy === 'type') {
			$orderSql = 'ORDER BY p.ID ' . ( $order === 'asc' ? 'ASC' : 'DESC' );
		}
		$results = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT p.ID, p.post_title, p.post_content as description, p.post_excerpt as caption, pm1.meta_value as alt, pm2.meta_value as path 
				FROM $wpdb->posts p 
				LEFT JOIN $wpdb->postmeta pm1 ON pm1.post_id = p.ID AND pm1.meta_key = '_wp_attachment_image_alt' 
				LEFT JOIN $wpdb->postmeta pm2 ON pm2.post_id = p.ID AND pm2.meta_key = '_wp_attached_file' 
				WHERE p.post_type='attachment' 
				AND p.post_status='inherit' 
				$orderSql 
				LIMIT %d, %d", $skip, $limit 
			), ARRAY_A
		);
		$data = [];
		if (count($results) > 0) {
			foreach ($results as $record) {
				$data[] = [
					'ID' => $record['ID'],
					'title' => $record['post_title'],
					'description' => $record['description'],
					'caption' => $record['caption'],
					'alt' => $record['alt'],
					'path' => $record['path'],
					'thumbnail_url' => $this->getThumbnailUrl($record['ID'], 'medium')
				];
			}
		}
		return new WP_REST_Response( [
			'success' => true,
			'data' => $data,
			'total' => $total,
		], 200 );
	}

	function rest_unassigned_entries($request) {
		$limit = sanitize_text_field( $request->get_param('limit') );
		$skip = sanitize_text_field( $request->get_param('skip') );
		$orderBy = sanitize_text_field( $request->get_param('orderBy') );
		$order = sanitize_text_field( $request->get_param('order') );
		$total = $this->count_unassigned_entries();
		$results = $this->core->list_unassigned(true, $limit, $skip, $orderBy, $order);
		$data = [];
		if (count($results) > 0) {
			foreach ($results as $obj_record) {
				$record = (array) $obj_record;
				$data[] = [
					'ID' => $record['ID'],
					'title' => $record['post_title'],
					'description' => $record['post_content'],
					'caption' => $record['post_excerpt'],
					'alt' => $this->getThumbnailAlt($record['ID']),
					'path' => $this->getThumbnailPath($record['ID']),
					'thumbnail_url' => $this->getThumbnailUrl($record['ID'], 'medium')
				];
			}
		}
		return new WP_REST_Response( [
			'success' => true,
			'data' => $data,
			'total' => $total,
		], 200 );
	}

	function count_unassigned_entries() {
		global $wpdb;
		$table_name = $wpdb->prefix . "lrsync_relations";
		$whereIsOriginal = "";
		if ( $this->core->wpml_media_is_installed() ) {
			global $sitepress;
			$tbl_wpml = $wpdb->prefix . "icl_translations";
			$language = $sitepress->get_default_language();
			$whereIsOriginal = "AND p.ID IN (SELECT element_id FROM $tbl_wpml WHERE element_type = 'post_attachment' AND language_code = '$language') ";
		}
		return (int)$wpdb->get_var( "SELECT COUNT(ID) FROM $wpdb->posts p
			WHERE post_status = 'inherit'
			AND post_mime_type <> ''
			AND p.ID NOT IN (SELECT wp_id FROM $table_name) " .
			$whereIsOriginal
		);
	}

	function rest_folder_content($request) {
		$params = $request->get_json_params();
		$folder_id = isset( $params['folder_id'] ) ? (int)$params['folder_id'] : null;
		$source = isset( $params['source'] ) ? $params['source'] : null;
		$collection_ids = $folder_id
			? $this->core->get_collections_from_folder($folder_id)
			: $this->get_root_folders_by_source($source);
		$data = [];
		foreach ($collection_ids as $collection_id) {
			$data[] = $this->core->get_collection($collection_id);
		}
		return new WP_REST_Response( [
			'success' => true,
			'data' => $data
		], 200 );
	}

	function rest_gallery_content( $request ) {
		$collectionId = sanitize_text_field( $request->get_param('collectionId') );
		$limit = sanitize_text_field( $request->get_param('limit') );
		$skip = sanitize_text_field( $request->get_param('skip') );
		$orderBy = sanitize_text_field( $request->get_param('orderBy') );
		$order = sanitize_text_field( $request->get_param('order') );

		// Get gallery based on wp_posts

		$mediaIds = $this->core->get_media_from_collection($collectionId);
		if (count($mediaIds) === 0) {
			return new WP_REST_Response( [
				'success' => true,
				'data' => [],
				'total' => 0,
			], 200 );
		}
		$mediaIdsPlaceholders = implode(', ', array_fill(0, count( $mediaIds ), '%s'));

		global $wpdb;
		$total = (int)$wpdb->get_var( $wpdb->prepare(
			"SELECT COUNT(ID) FROM $wpdb->posts p 
			WHERE post_type='attachment' 
			AND post_status='inherit' 
			AND ID IN (" . $mediaIdsPlaceholders . ")", $mediaIds
		));
		$orderSql = 'ORDER BY p.ID DESC ';
		if ($orderBy === 'type') {
			$orderSql = 'ORDER BY p.ID ' . ( $order === 'asc' ? 'ASC' : 'DESC' );
		}
		$results = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT p.ID, p.post_title, p.post_content as description, p.post_excerpt as caption, pm1.meta_value as alt, pm2.meta_value as path 
				FROM $wpdb->posts p 
				LEFT JOIN $wpdb->postmeta pm1 ON pm1.post_id = p.ID AND pm1.meta_key = '_wp_attachment_image_alt' 
				LEFT JOIN $wpdb->postmeta pm2 ON pm2.post_id = p.ID AND pm2.meta_key = '_wp_attached_file' 
				WHERE post_type='attachment' 
				AND post_status='inherit' 
				AND ID IN (" . $mediaIdsPlaceholders . ") 
				$orderSql 
				LIMIT %d, %d", array_merge( $mediaIds, array( $skip, $limit ) )
			), ARRAY_A
		);

		$data = [];
		if ( count( $results ) === 0 ) {
			return new WP_REST_Response( [
				'success' => true,
				'data' => $data,
				'total' => $total,
			], 200 );
		}

		// Prefer the order by clause if specified.
		if ($orderBy === 'type') {
			foreach ( $results as $record ) {
				$data[] = [
					'ID' => $record['ID'],
					'title' => $record['post_title'],
					'description' => $record['description'],
					'caption' => $record['caption'],
					'alt' => $record['alt'],
					'path' => $record['path'],
					'thumbnail_url' => $this->getThumbnailUrl( $record['ID'], 'medium' )
				];
			}
			return new WP_REST_Response( [
				'success' => true,
				'data' => $data,
				'total' => $total,
			], 200 );
		}

		// We need to keep the same order as the WPLR DB, hence this two loops.
		foreach ( $mediaIds as $mediaId ) {
			foreach ( $results as $record ) {
				if ( $record['ID'] === $mediaId ) {
					$data[] = [
						'ID' => $record['ID'],
						'title' => $record['post_title'],
						'description' => $record['description'],
						'caption' => $record['caption'],
						'alt' => $record['alt'],
						'path' => $record['path'],
						'thumbnail_url' => $this->getThumbnailUrl( $record['ID'], 'medium' )
					];
					break;
				}
			}
		}
		return new WP_REST_Response( [
			'success' => true,
			'data' => $data,
			'total' => $total,
		], 200 );
	}

	function format_hierarchy( $hierarchy ) {
		global $wpdb;
		$tbl_r = $wpdb->prefix . 'lrsync_relations';
		foreach ( $hierarchy as $key => $c ) {
			$is_folder = $c['type'] === 'folder';
			$is_collection = $c['type'] === 'collection';
			$hierarchy[$key]['is_folder'] = $is_folder;
			$hierarchy[$key]['is_collection'] = $is_collection;
			$hierarchy[$key]['featured_image_id'] = $c['featured_id'] ?? null;
			$hierarchy[$key]['featured_image'] = $c['featured_id'] ? $this->getThumbnailUrl($c['featured_id'], 'thumbnail') : null;
			unset($hierarchy[$key]['featured_id']);
			if ( $is_folder ) {
				$hierarchy[$key]['children'] = $this->format_hierarchy( $c['children'] );
			}
			if ( $is_collection ) {
				$children = [];
				// In fact, we are only interested in the count here, so let's avoid a heavy request.
				$children = array_fill(0, $hierarchy[$key]['count'], '');
				$hierarchy[$key]['children'] = $children;
			}
		}
		return $hierarchy;
	}

	function rest_delete_hierarchy($request) {
		$params = $request->get_json_params();
		$delete_collection = isset( $params['delete_collection'] ) ? $params['delete_collection'] : null;

		if (!$delete_collection) {
			return new WP_REST_Response([
				'success' => false,
				'message' => 'delete_collection is missing.',
			], 400 );
		}
		$data = $this->core->delete_collection( $delete_collection );
		return new WP_REST_Response( [ 'success' => true, 'data' => $data ], 200 );
	}

	function rest_keywords_hierarchy() {
		$hierarchy = $this->core->get_keywords_hierarchy();
		return new WP_REST_Response( [
			'success' => true,
			'data' => $hierarchy
		], 200 );
	}

	function rest_delete_keywords_hierarchy($request) {
		$params = $request->get_json_params();
		$delete_keyword = isset( $params['delete_keyword'] ) ? $params['delete_keyword'] : null;

		if (!$delete_keyword) {
			return new WP_REST_Response([
				'success' => false,
				'message' => 'delete_keyword is missing.',
			], 400 );
		}
		$data = $this->core->delete_keyword( $delete_keyword );
		return new WP_REST_Response( [ 'success' => true, 'data' => $data ], 200 );
	}

	function rest_entries( $request ) {
		$show = sanitize_text_field( $request->get_param( 'show' ) );
		if ( empty( $show ) ) {
			return new WP_REST_Response( [ 'success' => false, 'message' => 'Missing show parameter.' ], 400 );
		}
		$entries = [];
		if ( $show === 'duplicates' ) {
			$entries = $this->core->list_duplicates();
			foreach ( $entries as $entry ) {
				$wpids = explode( ',', $entry->wpids );
				$details = [];
				foreach ($wpids as $wpid) {
					$details[] = [
						'thumbnail_url' => $this->getThumbnailUrl( $wpid, 'thumbnail' ),
						'ID' => $wpid
					];
				}
				$entry->details = $details;
			}
			return new WP_REST_Response( [ 'success' => true, 'data' => $entries ], 200 );
		}
		elseif ( $show === 'ignored' ) {
			$entries = $this->core->list_ignored();
		}
		else {
			$entries = $this->core->list_unlinks( true );
		}
		foreach ( $entries as $entry ) {
			$entry->thumbnail_url = $this->getThumbnailUrl( $entry->ID, 'thumbnail' );
		}
		return new WP_REST_Response( [ 'success' => true, 'data' => $entries ], 200 );
	}

	function rest_sync_info( $request ) {
		$params = $request->get_json_params();
		$wpIds = isset( $params['wpIds'] ) ? (array)$params['wpIds'] : null;
		$wpId = isset( $params['wpId'] ) ? (int)$params['wpId'] : null;
		$data = array();
		if ( !empty( $wpIds ) ) {
			foreach ( $wpIds as $wpId ) {
				$entry = $this->core->get_sync_info( $wpId );
				array_push( $data, $entry );
			}
		}
		else if ( !empty( $wpId ) ) {
			$data = $this->core->get_sync_info( $wpId );
		}
		return new WP_REST_Response( [ 'success' => true, 'data' => $data ], 200 );
	}

	function rest_update_option( $request ) {
		$params = $request->get_json_params();
		try {
			$name = $params['name'];
			$options = $this->admin->list_options();
			if ( !array_key_exists( $name, $options ) ) {
				return new WP_REST_Response([ 'success' => false, 'message' => 'This option does not exist.' ], 200 );
			}
			$value = is_bool( $params['value'] ) ? ( $params['value'] ? '1' : '' ) : $params['value'];
			$success = update_option( $name, $value );
			if ( $success ) {
				$res = $this->validate_updated_option( $name );
				$result = $res['result'];
				$message = $res['message'];
				return new WP_REST_Response([ 'success' => $result, 'message' => $message ], 200 );
			}
			return new WP_REST_Response([ 'success' => false, 'message' => "Could not update option." ], 200 );
		} 
		catch (Exception $e) {
			return new WP_REST_Response([
				'success' => false,
				'message' => $e->getMessage(),
			], 500 );
		}
	}

	function validate_updated_option( $option_name ) {
		$wplr_library_show_hierarchy = get_option( 'wplr_library_show_hierarchy', 'none' );
		$wplr_public_api = get_option( 'wplr_public_api', false );
		if ( $wplr_library_show_hierarchy === '' )
			update_option( 'wplr_library_show_hierarchy', 'none' );
		if ( $wplr_public_api === '' )
			update_option( 'wplr_public_api', false );
		if (!get_option( 'wplr_public_api', false ) && get_transient( 'wplr_auth_token' ) !== false) {
			delete_transient( 'wplr_auth_token' );
		}
		return $this->createValidationResult();
	}

	function createValidationResult( $result = true, $message = null) {
		$message = $message ? $message : __( 'OK', 'wplr-sync' );
		return ['result' => $result, 'message' => $message];
	}

	function rest_unlink($request) {
		$params = $request->get_json_params();
		$lr_id = isset( $params['lrId'] ) ? (int)$params['lrId'] : null;
		$wp_id = isset( $params['wpId'] ) ? (int)$params['wpId'] : null;
		$afterDelete = isset( $params['afterDelete'] ) ? (int)$params['afterDelete'] : false;

		list($result, $message, $code) = $this->validate_link_unlink($lr_id, $wp_id);

		if (!$result) {
			return new WP_REST_Response([
				'success' => $result,
				'message' => $message,
			], $code );
		}

		$result = $this->core->unlink_media( $lr_id, $wp_id );

		if ($result && $afterDelete) {
			wp_delete_attachment( $wp_id );
		}

		return new WP_REST_Response([
			'success' => $result,
			'data' => !$result ? null : [
				'wp_id' => $wp_id,
				'lr_id' => null
			],
			'message' => $result ? 'Success.' : $this->core->get_error(),
		], 200 );
	}

	function rest_link($request) {
		$params = $request->get_json_params();
		$lr_id = isset( $params['lrId'] ) ? (int)$params['lrId'] : null;
		$wp_id = isset( $params['wpId'] ) ? (int)$params['wpId'] : null;

		list($result, $message, $code) = $this->validate_link_unlink($lr_id, $wp_id);

		if (!$result) {
			return new WP_REST_Response([
				'success' => $result,
				'message' => $message,
			], $code );
		}

		$sync = $this->core->link_media( $lr_id, $wp_id );
		$result = (bool)$sync;
		return new WP_REST_Response([
			'success' => $result,
			'data' => !$result ? null : [
				'wp_id' => $wp_id,
				'lr_id' => $sync->lr_id,
				'lastsync' => $sync->lastsync
			],
			'message' => $result ? 'Success.' : $this->core->get_error(),
		], 200 );
	}

	function rest_extensions_query($request) {
		$params = $request->get_json_params();
		$task = isset( $params['task'] ) ? (array)$params['task'] : null;
		if (!$task)
			return new WP_REST_Response([
				'success' => false,
				'data' => 'The parameter task was missing.'
			], 500 );
		try {
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
				$pTagParent = $this->core->get_meta( 'tag_parent', (int)$task['id'] );
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

			return new WP_REST_Response([
				'success' => true,
			], 200 );
		}
		catch ( Exception $e ) {
			error_log( print_r( $e, true ) );
			return new WP_REST_Response([
				'success' => false,
				'message' => 'An exception was caught and written in the PHP error logs.',
			], 500 );
		}
	}

	function rest_extensions_init($request) {
		global $wpdb;
		$params = $request->get_json_params();
		$isRemoval = isset( $params['is_removal'] ) && $params['is_removal'] == 1;
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
		$collections = $this->core->read_collections_recursively( null, array(), $isRemoval );
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

		return new WP_REST_Response([
			'success' => true,
			'data' => $isRemoval ? $tasks : array_reverse( $tasks )
		], 200 );
	}

	function rest_extensions_reset() {
		try {
			do_action( 'wplr_reset' );
			return new WP_REST_Response([
				'success' => true,
			], 200 );
		}
		catch ( Exception $e ) {
			error_log( print_r( $e, true ) );
			return new WP_REST_Response([
				'success' => false,
				'data' => 'An exception was caught and written in the PHP error logs.'
			], 500 );
		}
	}

	function rest_clean() {
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
			meow_wplrsync_activate();
			return new WP_REST_Response([
				'success' => true,
			], 200 );
		}
		catch ( Exception $e ) {
			error_log( print_r( $e, true ) );
			return new WP_REST_Response([
				'success' => false,
				'data' => 'An exception was caught and written in the PHP error logs.'
			], 500 );
		}
	}

	function rest_repair() {
		$messages = $this->core->check_db();

		if ( empty( $messages ) ) {
			$messages[] = '🟢 No issues found.';
		}

		return new WP_REST_Response([
			'success' => true,
			'data' => $messages
		], 200 );
	}

	function rest_create_folder($request) {
		$params = $request->get_json_params();
		$name = isset( $params['name'] ) ? $params['name'] : '';
		$parentFolderId = isset( $params['parent_folder_id'] ) ? $params['parent_folder_id'] : null;
		$source = isset( $params['source'] ) ? $params['source'] : '';

		if (!$name || !$source) {
			return new WP_REST_Response([
				'success' => false,
				'message' => 'The create folder parameters are missing.',
			], 400 );
		}
		if (!$this->core->create_collection('folder', $name, $parentFolderId, $source)) {
			return new WP_REST_Response([
				'success' => false,
				'message' => 'Failed to create a new folder.',
			], 400 );
		}

		return new WP_REST_Response([
			'success' => true,
		], 200 );
	}

	function rest_create_gallery($request) {
		$params = $request->get_json_params();
		$name = isset( $params['name'] ) ? $params['name'] : '';
		$parentFolderId = isset( $params['parent_folder_id'] ) ? $params['parent_folder_id'] : null;
		$source = isset( $params['source'] ) ? $params['source'] : '';

		if (!$name || !$source) {
			return new WP_REST_Response([
				'success' => false,
				'message' => 'The create gallery parameters are missing.',
			], 400 );
		}
		if (!$this->core->create_collection('collection', $name, $parentFolderId, $source)) {
			return new WP_REST_Response([
				'success' => false,
				'message' => 'Failed to create a new gallery.',
			], 400 );
		}

		return new WP_REST_Response([
			'success' => true,
		], 200 );
	}

	function rest_update_folder($request) {
		$params = $request->get_json_params();
		$wp_col_id = isset( $params['id'] ) ? $params['id'] : '';
		$name = isset( $params['name'] ) ? $params['name'] : '';
		$slug = isset( $params['slug'] ) ? $params['slug'] : '';

		if ( !$wp_col_id || !$name ) {
			return new WP_REST_Response([
				'success' => false,
				'message' => 'The update folder parameters are missing.',
			], 400 );
		}

		try {
			$this->core->update_collection( $wp_col_id, $name, $slug );
			return new WP_REST_Response([
				'success' => true,
			], 200 );
		}
		catch (Exception $e) {
			return new WP_REST_Response([
				'success' => false,
				'message' => $e->getMessage(),
			], 500 );
		}
	}

	function rest_update_gallery($request) {
		$params = $request->get_json_params();
		$wp_col_id = isset( $params['id'] ) ? $params['id'] : '';
		$name = isset( $params['name'] ) ? $params['name'] : '';
		$slug = isset( $params['slug'] ) ? $params['slug'] : '';

		if (!$wp_col_id || !$name) {
			return new WP_REST_Response([
				'success' => false,
				'message' => 'The update gallery parameters are missing.',
			], 400 );
		}

		try {
			$this->core->update_collection( $wp_col_id, $name, $slug );
			return new WP_REST_Response([
				'success' => true,
			], 200 );
		}
		catch (Exception $e) {
			return new WP_REST_Response([
				'success' => false,
				'message' => $e->getMessage(),
			], 500 );
		}
	}

	function rest_delete_collection($request) {
		$params = $request->get_json_params();
		$wpColId = isset( $params['id'] ) ? (int)$params['id'] : '';

		if (!$wpColId) {
			return new WP_REST_Response([
				'success' => false,
				'message' => 'The folder id or the gallery id to delete is missing.',
			], 400 );
		}
		if (!$this->core->delete_collection($wpColId)) {
			return new WP_REST_Response([
				'success' => false,
				'message' => 'Failed to delete the folder/gallery.',
			], 400 );
		}

		return new WP_REST_Response([
			'success' => true,
		], 200 );
	}

	function rest_move_collection($request) {
		$params = $request->get_json_params();
		$wp_col_ids = isset( $params['ids'] ) ? $params['ids'] : '';
		$parent_folder_id = (isset( $params['parent_id'] ) || is_null( $params['parent_id'] )) ? $params['parent_id'] : '';
		if (!count($wp_col_ids) || $parent_folder_id === '') {
			return new WP_REST_Response([
				'success' => false,
				'message' => 'The id to move or parent id is missing.',
			], 400 );
		}
		try {
			foreach ($wp_col_ids as $wp_col_id) {
				$this->core->move_collection($wp_col_id, $parent_folder_id);
			}
			return new WP_REST_Response([
				'success' => true,
			], 200 );
		}
		catch (Exception $e) {
			return new WP_REST_Response([
				'success' => false,
				'message' => $e->getMessage(),
			], 500 );
		}
	}

	function rest_move_media($request) {
		$params = $request->get_json_params();
		$wp_ids = isset( $params['ids'] ) ? $params['ids'] : '';
		$new_wp_col_id = isset( $params['new_col_id'] ) ? $params['new_col_id'] : '';
		$previous_wp_col_id = isset( $params['current_col_id'] ) ? $params['current_col_id'] : '';
		if (!count($wp_ids) || !$new_wp_col_id) {
			return new WP_REST_Response([
				'success' => false,
				'message' => 'The id to move, new collection id, or current collection id is missing.',
			], 400 );
		}
		try {
			foreach ($wp_ids as $wp_id) {
				if ($this->core->add_media_to_collection($wp_id, $new_wp_col_id) === false) {
					throw new Exception($this->core->get_error());
				}
				if ($previous_wp_col_id) {
					$this->core->remove_media_from_collection($wp_id, $previous_wp_col_id);
				}
			}
			return new WP_REST_Response([
				'success' => true,
			], 200 );
		}
		catch (Exception $e) {
			return new WP_REST_Response([
				'success' => false,
				'message' => $e->getMessage(),
			], 500 );
		}
	}

	function rest_copy_media($request) {
		$params = $request->get_json_params();
		$wp_ids = isset( $params['ids'] ) ? $params['ids'] : '';
		$new_wp_col_id = isset( $params['new_col_id'] ) ? $params['new_col_id'] : '';
		if (!count($wp_ids) || $new_wp_col_id === '') {
			return new WP_REST_Response([
				'success' => false,
				'message' => 'The media id or a collection id is missing.',
			], 400 );
		}
		try {
			foreach ($wp_ids as $wp_id) {
				if ($this->core->add_media_to_collection($wp_id, $new_wp_col_id) === false) {
					throw new Exception($this->core->get_error());
				}
			}
			return new WP_REST_Response([
				'success' => true,
			], 200 );
		}
		catch (Exception $e) {
			return new WP_REST_Response([
				'success' => false,
				'message' => $e->getMessage(),
			], 500 );
		}
	}

	function rest_remove_media($request) {
		$params = $request->get_json_params();
		$wp_ids = isset( $params['ids'] ) ? $params['ids'] : '';
		$previous_wp_col_id = isset( $params['current_col_id'] ) ? $params['current_col_id'] : '';
		if (!count($wp_ids) || !$previous_wp_col_id) {
			return new WP_REST_Response([
				'success' => false,
				'message' => 'The id to move or current collection id is missing.',
			], 400 );
		}
		try {
			foreach ($wp_ids as $wp_id) {
				$this->core->remove_media_from_collection($wp_id, $previous_wp_col_id);
			}
			return new WP_REST_Response([
				'success' => true,
			], 200 );
		}
		catch (Exception $e) {
			return new WP_REST_Response([
				'success' => false,
				'message' => $e->getMessage(),
			], 500 );
		}
	}

	function rest_update_media($request) {
		$params = $request->get_json_params();
		$wp_id = isset( $params['id'] ) ? $params['id'] : '';
		$title = isset( $params['title'] ) ? $params['title'] : '';
		$description = isset( $params['description'] ) ? $params['description'] : '';
		$caption = isset( $params['caption'] ) ? $params['caption'] : '';
		$alt = isset( $params['alt'] ) ? $params['alt'] : '';
		if (!$wp_id) {
			return new WP_REST_Response([
				'success' => false,
				'message' => 'The id to move or current collection id is missing.',
			], 400 );
		}
		try {
			$post = [
				'ID' => $wp_id,
				'post_title' => $title,
				'post_content' => $description,
				'post_excerpt' => $caption
			];
			$result = wp_update_post( $post, true );
			if ( is_wp_error( $result ) ) {
				throw new Exception($result->get_error_message());
			}
			update_post_meta( $wp_id, '_wp_attachment_image_alt', $alt );

			return new WP_REST_Response([
				'success' => true,
			], 200 );
		}
		catch (Exception $e) {
			return new WP_REST_Response([
				'success' => false,
				'message' => $e->getMessage(),
			], 500 );
		}
	}

	public function rest_update_featured_image($request) {
		$params = $request->get_json_params();
		$collection_id = isset( $params['collection_id'] ) ? $params['collection_id'] : '';
		$featured_image_id = isset( $params['featured_image_id'] ) ? $params['featured_image_id'] : '';
		if (!$collection_id || !$featured_image_id ) {
			return new WP_REST_Response([
				'success' => false,
				'message' => 'The featured image id or current collection id is missing.',
			], 400 );
		}
		try {
			$this->core->set_featured_image($collection_id, $featured_image_id);

			return new WP_REST_Response([
				'success' => true,
			], 200 );
		}
		catch (Exception $e) {
			return new WP_REST_Response([
				'success' => false,
				'message' => $e->getMessage(),
			], 500 );
		}
	}

	/**
	 * Private Methods
	 */
	private function validate_link_unlink($lr_id, $wp_id)
	{
		if ( !current_user_can('upload_files') ) {
			return [ false, 'You do not have the roles to perform this action.', 403 ];
		}
		if ( $lr_id === '' || $lr_id === null || $wp_id === '' || $wp_id === null ) {
			return [ false, 'Some information is missing.', 422 ];
		}
		return [ true, null, null ];
	}

	private function getThumbnailUrl($id, $size)
	{
		$attachment_src = wp_get_attachment_image_src( $id, $size );
		return empty( $attachment_src ) ? null : $attachment_src[0];
	}

	private function getThumbnailAlt($id)
	{
		return get_post_meta( $id, '_wp_attachment_image_alt', true );
	}

	private function getThumbnailPath($id)
	{
		return get_post_meta( $id, '_wp_attached_file', true );
	}

	/**
	 * Get the folders which have no wp_folder_id in the specific source.
	 *
	 * @param string $source
	 * @return array
	 */
	private function get_root_folders_by_source( $source ) {
		global $wpdb;
		$tbl_c = $wpdb->prefix . 'lrsync_collections';
		$collections = $wpdb->get_col( $wpdb->prepare( "SELECT wp_col_id FROM $tbl_c
			WHERE wp_folder_id IS NULL AND source = %s ORDER BY name, lr_col_id", $source ) );
		return $collections;
	}
}
