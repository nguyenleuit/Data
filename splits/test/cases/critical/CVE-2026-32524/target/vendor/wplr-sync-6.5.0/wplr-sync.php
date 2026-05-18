<?php
/*
Plugin Name: Photo Engine (WP/LR Sync)
Plugin URI: https://meowapps.com
Description: Synchronize and maintain your photos, collections, keywords and metadata between Lightroom and WordPress.
Version: 6.5.0
Author: Jordy Meow
Author URI: https://meowapps.com
Text Domain: wplr-sync
Domain Path: /languages

Originally developed for two of my websites:
- Jordy Meow (https://offbeatjapan.org)
- Haikyo (https://haikyo.org)
*/

define( 'WPLR_SYNC_VERSION', '6.5.0' );
define( 'WPLR_SYNC_PREFIX', 'wplr_sync' );
define( 'WPLR_SYNC_DOMAIN', 'wplr-sync' );
define( 'WPLR_SYNC_ENTRY', __FILE__ );
define( 'WPLR_SYNC_PATH', dirname( __FILE__ ) );
define( 'WPLR_SYNC_URL', plugin_dir_url( __FILE__ ) );

require_once( 'classes/init.php');

?>
