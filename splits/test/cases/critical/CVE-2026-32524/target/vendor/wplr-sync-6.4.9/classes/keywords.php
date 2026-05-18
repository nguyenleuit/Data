<?php

class Meow_WPLR_Sync_Keywords {

	private $tax = null;

	public function __construct() {

		// Enable Keywords
		$wplr_enable_keywords = get_option( 'wplr_enable_keywords', false );
		if ( $wplr_enable_keywords ) {
			$labels = array(
	      'name'              => _x( 'Keywords', 'taxonomy general name' ),
	      'singular_name'     => _x( 'Keyword', 'taxonomy singular name' ),
	      'search_items'      => __( 'Search Keywords' ),
	      'all_items'         => __( 'All Keywords' ),
	      'parent_item'       => __( 'Parent Keyword' ),
	      'parent_item_colon' => __( 'Parent Keyword:' ),
	      'edit_item'         => __( 'Edit Keyword' ),
	      'update_item'       => __( 'Update Keyword' ),
	      'add_new_item'      => __( 'Add New Keyword' ),
	      'new_item_name'     => __( 'New Keyword Name' ),
	      'menu_name'         => __( 'Keywords' )
	    );
			$args = array(
	      'hierarchical'          => true,
				'public'                => true,
				'publicly_queryable'		=> true,
	      'labels'                => $labels,
	      'show_ui'               => true,
	      'show_admin_column'     => true,
	      'query_var'             => true,
	      'update_count_callback' => '_update_generic_term_count',
	      'rewrite'               => array( 'slug' => 'keyword' )
	    );
	    register_taxonomy( 'attachment_keyword', array( 'attachment' ), $args );
		}

		// Enable Sync Keywords
		$this->tax = get_option( 'wplr_sync_keywords', false );

		if ( !$wplr_enable_keywords && $this->tax == 'attachment_keyword' ) {
			delete_option( 'wplr_sync_keywords' );
			$this->tax = null;
		}

		if ( !empty( $this->tax ) ) {
			add_action( "wplr_add_tag", array( $this, 'add_tag' ), 10, 3 );
      add_action( "wplr_update_tag", array( $this, 'update_tag' ), 10, 3 );
      add_action( "wplr_remove_tag", array( $this, 'remove_tag' ), 10, 1 );
      add_action( "wplr_add_media_tag", array( $this, 'add_media_tag' ), 10, 2 );
      add_action( "wplr_remove_media_tag", array( $this, 'remove_media_tag' ), 10, 2 );
		}

		// Make sure media items are retrieved when we visit the archive pages
		// for the keywords.
		add_filter( 'pre_get_posts', array( $this, 'pre_get_posts' ) );

		// From WordPress 5.5, we need to remove the keywords page from the sitemap
		//add_filter( 'wp_sitemaps_taxonomies', array( $this, 'wp_sitemaps_taxonomies' ) );
	}

	function pre_get_posts( $query ) {
    if ( $query->is_tax( 'attachment_keyword' ) && $query->is_main_query() ) {
      $query->set( 'post_status', 'inherit' );
    }
    return $query;
	}

	function wp_sitemaps_taxonomies( $taxonomies ) {
		unset( $taxonomies['attachment_keyword'] );
		return $taxonomies;
	}

  function add_tag( $tagId, $name, $parentId ) {
		global $wplr;
    $wplr->create_taxonomy( $tagId, $parentId, array( 'name' => $name ), $this->tax, 'wplr_keyword_tax_id' );
  }

  function update_tag( $tagId, $name ) {
		global $wplr;
    $wplr->update_taxonomy( $tagId, array( 'name' => $name ), $this->tax, 'wplr_keyword_tax_id' );
  }

  function remove_tag( $tagId ) {
		global $wplr;
    $wplr->remove_taxonomy( $tagId, $this->tax, 'attachment', 'wplr_keyword_tax_id' );
  }

  function add_media_tag( $mediaId, $tagId ) {
		global $wplr;
    $wplr->add_taxonomy_to_posttype( $tagId, $mediaId, $this->tax, null, 'wplr_keyword_tax_id' );
  }

  function remove_media_tag( $mediaId, $tagId ) {
		global $wplr;
    $wplr->remove_taxonomy_from_posttype( $tagId, $mediaId, $this->tax, null, 'wplr_keyword_tax_id' );
  }

}
