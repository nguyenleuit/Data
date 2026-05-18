<?php

function meow_wplrsync_activate()
{
  global $wpdb;
  require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
  $charset_collate = $wpdb->get_charset_collate();
  $tbl_lrsync = $wpdb->prefix . "lrsync";
  $sql = "CREATE TABLE $tbl_lrsync (
		id BIGINT(20) NOT NULL AUTO_INCREMENT,
		wp_id BIGINT(20) NULL,
		lr_id BIGINT(20) NULL,
		lr_file TINYTEXT NULL,
		lastsync DATETIME NULL,
		PRIMARY KEY id (id)
	) " . $charset_collate . ";";
  dbDelta($sql);
  $tbl_collections = $wpdb->prefix . "lrsync_collections";
  $isNewToCollections = ($wpdb->get_var("SHOW TABLES LIKE '$tbl_collections'") != $tbl_collections);
  $sql = "CREATE TABLE $tbl_collections (
		wp_col_id BIGINT(20) NOT NULL AUTO_INCREMENT,
        source TINYTEXT NULL,
		lr_col_id BIGINT(20) NULL,
		wp_folder_id BIGINT(20) NULL,
		name TINYTEXT NULL,
        slug TINYTEXT NULL,
		is_folder TINYINT(1) NOT NULL DEFAULT 0,
        featured_id BIGINT(20) NULL,
		lastsync DATETIME NULL,
		PRIMARY KEY id (wp_col_id)
    ) " . $charset_collate . ";";
  dbDelta($sql);
  $tbl_relations = $wpdb->prefix . "lrsync_relations";
  $sql = "CREATE TABLE $tbl_relations (
        id BIGINT(20) NOT NULL AUTO_INCREMENT,
		wp_col_id BIGINT(20) NULL,
		wp_id BIGINT(20) NULL,
		sort INT(11) DEFAULT 0,
        PRIMARY KEY id (id),
		UNIQUE KEY id (wp_col_id, wp_id)
	) " . $charset_collate . ";";
  dbDelta($sql);
  $tbl_meta = $wpdb->prefix . "lrsync_meta";
  $isNewToCollections = ($wpdb->get_var("SHOW TABLES LIKE '$tbl_meta'") != $tbl_meta);
  $sql = "CREATE TABLE $tbl_meta (
		meta_id BIGINT(20) NOT NULL AUTO_INCREMENT,
		name TINYTEXT NULL,
		id BIGINT(20) NULL,
		value LONGTEXT NULL,
		PRIMARY KEY id (meta_id)
	) " . $charset_collate . ";";
  dbDelta($sql);

  // If this install is new to Collections, insert all the linked
  // media in the -1 collection (default one)
  if ($isNewToCollections) {
    $wpdb->query("INSERT INTO $tbl_relations (wp_col_id, wp_id, sort) SELECT -1, wp_id, 0 FROM $tbl_lrsync");
  }

  // The source might be missing, it needs to be set and by default it's Lightroom.
  $wpdb->query($wpdb->prepare("UPDATE $tbl_collections SET source = '%s' WHERE source IS NULL OR source = ''", 'lr'));
  // This is more like cleaning and making sure wp_folder_id is null instead of 0 (that happened to someone somehow).
  $wpdb->query("UPDATE $tbl_collections SET wp_folder_id = NULL WHERE wp_folder_id = '0'");
}

function meow_wplrsync_uninstall() {
  // Better to avoid removing the table...
  global $wpdb;
  $tbl_col = $wpdb->prefix . 'lrsync_collections';
  $tbl_r = $wpdb->prefix . 'lrsync_relations';
  $tbl_m = $wpdb->prefix . 'lrsync_meta';
  $tbl_lr = $wpdb->prefix . 'lrsync';
  $wpdb->query("DROP TABLE IF EXISTS $tbl_col");
  $wpdb->query("DROP TABLE IF EXISTS $tbl_r");
  $wpdb->query("DROP TABLE IF EXISTS $tbl_lr");
  $wpdb->query("DROP TABLE IF EXISTS $tbl_m");
}

spl_autoload_register(function ($class) {
  $necessary = true;
  $file = null;
  if (strpos($class, 'Meow_WPLR_Sync') !== false) {
    $file = WPLR_SYNC_PATH . '/classes/' . str_replace('meow_wplr_sync_', '', strtolower($class)) . '.php';
  } else if (strpos($class, 'MeowKit_WPLR_') !== false) {
    $file = WPLR_SYNC_PATH . '/common/' . str_replace('meowkit_wplr_', '', strtolower($class)) . '.php';
  } else if (strpos($class, 'MeowKitPro_WPLR_') !== false) {
    $file = WPLR_SYNC_PATH . '/common/premium/' . str_replace('meowkitpro_wplr_', '', strtolower($class)) . '.php';
  } else if (strpos($class, 'MeowPro_WPLR_Sync') !== false) {
    $necessary = false;
    $file = WPLR_SYNC_PATH . '/premium/' . str_replace('meowpro_wplr_sync_', '', strtolower($class)) . '.php';
  }
  if ($file) {
    if (!$necessary && !file_exists($file)) {
      return;
    }
    require($file);
  }
});

//require_once( WPLR_SYNC_PATH . '/classes/api.php');
require_once(WPLR_SYNC_PATH . '/common/helpers.php');

global $wplr;
$wplr = new Meow_WPLR_Sync_Core();
