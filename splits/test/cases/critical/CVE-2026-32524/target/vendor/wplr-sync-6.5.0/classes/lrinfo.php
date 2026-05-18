<?php

class Meow_WPLR_Sync_LRInfo {

	// Core
	public $lr_id; // LR ID (ID used by Lightroom DB)
	public $lr_file; // Original filename given by LR
	public $lr_title; // Original title given by LR
	public $lr_caption; // Original caption given by LR
	public $lr_desc; // Original description given by LR
	public $lr_alt_text; // Original ALT text given by LR
	public $wp_id; // Media ID in WordPress
	public $lastsync; // Time of the latest synchronization

	// Conditions (only used during synchronization)
	public $sync_title; // Boolean: replace the existing title with the one given by LR
	public $sync_caption; // Boolean: replace the existing caption with the one given by LR
	public $sync_alt_text; // Boolean: replace the existing ALT text with the one given by LR
	public $sync_desc; // Boolean: replace the existing description with the one given by LR

	// Extra (only used during synchronization)
	public $type; // MIME type given by LR (will be used as the post_mime_type for the Media)
	public $tags; // Keywords given by LR

	// WP
	public $wp_url; // URL of the attachment
	public $wp_phash; // Perceptual Hash (for Total Synchronization)
	public $wp_exif; // Exif Image Creation Date (for Total Synchronization)

	function __construct() {
	}

	public function __toString() {
		return $this->toJSON();
	}

	public static function fromRow( $row ) {
		$instance = new self();
		$instance->lr_id = $row->lr_id;
		$instance->lr_file = $row->lr_file;
		$instance->wp_id = $row->wp_id;
		$instance->lastsync = $row->lastsync;
		return $instance;
	}

	public function toArray() {
		return get_object_vars( $this );
	}

	public function toJSON() {
		return json_encode( $this->toArray() );
	}
}

?>
