=== Photo Engine (Media Organizer & Lightroom) ===
Contributors: TigrouMeow
Tags: lightroom, sync, export, image, manager
Donate link: https://www.patreon.com/meowapps
License: GPLv3
Requires at least: 6.0
Tested up to: 6.9
Requires PHP: 7.4
Stable tag: 6.5.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Organize your photos in folders and collections. Synchronize with Lightroom. Make your life easier! :)

== Description ==

**Media Organizer**. You can now organize your photos in folders and collections. From those collections, you will be able to create galleries easily, without the need of a specific plugin.

**Synchronize with Lightroom**. Upload and keep your photos, collections, keywords and metadata synchronized with WordPress. Then, for instance, modifying your photos, their quality, or changing your watermark on all of them at once will be easy!

Learn more about it all here: [Photo Engine](https://meowapps.com/wplr-sync/).

=== Media Organizer ===

You can use attributes (collections='...', keywords='...') in the standard WP Gallery shortcode to link your galleries to your collections and keywords. No need to own a specific plugin or anything, it works naturally with WordPress. The [Meow Gallery](https://wordpress.org/plugins/meow-gallery/) and the [Meow Lightbox](https://wordpress.org/plugins/meow-lightbox/) are recommended to enhance your galleries with better layouts and options. They can directly get your collections.

=== Synchronize with Lightroom ===

If your plan is to synchronize Lightroom with WordPress, you will also need the WP/LR Sync Plugin for Lightroom. Please have a look at the official website of [Photo Engine](https://meowapps.com/wplr-sync/) for more information.

Do you have many photos in your WordPress already and they are not linked with your Lightroom? No problem, Photo Engine can do that too. Using EXIF and image perceptual analysis, the plugin will help you linking them through a process call Total Synchronization or you can do it manually. The process is explained here: [Total Synchronization](https://meowapps.com/wplr-sync/tutorial/).

You are using a certain photo everywhere but you now have a better one? From Lightroom, you can swap one photo to another and this will be replicated automatically on your WordPress. You have nothing else to do. The module is called "Switch Photos" in Lightroom.

=== Support for Themes and Plugins ===

If you are using specific gallery plugins or photography themes, Photo Engine can bring all the power of Lightroom to them, magically, seamlessly. You will be free to choose the theme or gallery plugin you like the best and even switch between them. Photo Engine has a built-in extensions system so that you can extend it easily and support specific themes and plugins. A powerful extension called "Post Types" is already included and probably does everything you need. More information about it here: [Post Types Extension](https://meowapps.com/wplr-sync/tutorial/).

=== API & External Apps ===

There is an external API available through Photo Engine that iPhone, Android developers or anybody else can use to make apps. There is one available for iPhone, you can search for it on the iTunes Store (it is not free, and not made by Meow Apps).

=== Unique & Powerful Plugin ===

I am myself an user of this plugin and even though it is the only one, I want to make it better every day. If you have issues, frustrations, or anything to say, contact me. I will work hard to make it even more awesome.

Languages: English, Spanish (by [Nahuai Badiola](https://nbadiola.com)). If you want to translate the plugin in another language, please contact me :)

== Installation ==

1. Upload `wplr-sync` to the `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Install the Lightroom plugin from [here](https://meowapps.com/products/wplr-sync/).
4. Synchronize everything :)

== Upgrade Notice ==

Replace all the files. Nothing else to do.

== Frequently Asked Questions ==

Official FAQ is [here](https://meowapps.com/wplr-sync/issues/).

== Changelog ==

= 6.5.0 (2026/02/25) =
* Fix: Validate file types before syncing in the Lightroom Sync API.
* Add: Enable drag-and-drop reordering of photos within the same collection.
* Update: Improve gallery shortcode indicators in folders and collections.
* 🎵 Discuss with others about Wplr Sync on [the Discord](https://discord.gg/bHDGh38).
* 🌴 Keep us motivated with [a little review here](https://wordpress.org/support/plugin/wplr-sync/reviews/). Thank you!
* 🥰 If you want to help us, check our [Patreon](https://www.patreon.com/meowapps). Thank you!

= 6.4.9 (2026/01/27) =
* Fix: Prevent errors by checking if AttachmentFilters exists before adding the taxonomy.
* Fix: Improve hidden filter behavior.
* Update: Improve error handling for logging and metadata generation.
* Fix: Hotfix undefined call to onSelectFilter to avoid errors when selecting filters.

= 6.4.8 (2025/12/03) =
* Fix: Resolved a useEffect re-render loop in the Media Organizer.
* Fix: Corrected an array offset warning in admin debug mode.
* Fix: Added error handling for PHasher to prevent crashes when processing invalid images.
* 🎵 Discuss with others about Wplr Sync on [the Discord](https://discord.gg/bHDGh38).
* 🌴 Keep us motivated with [a little review here](https://wordpress.org/support/plugin/wplr-sync/reviews/). Thank you!
* 🥰 If you want to help us, check our [Patreon](https://www.patreon.com/meowapps). Thank you!

= 6.4.7 (2025/11/13) =
* Update: Upgraded to MeowKit.
* Fix: Corrected display issues.

= 6.4.6 (2025/09/29) =
* Update: Validation checks to ensure collections are properly synchronized.

= 6.4.5 (2025/08/27) =
* Fix: Corrected typos.
* Updated: A better shortcode.

= 6.4.4 (2025/07/23) =
* Update: Replaced deprecated Google Charts QR code generator with QRServer.
* Fix: Enhanced database checks.
* Update: Refreshed and optimized common libraries.

= 6.4.3 (2024/10/17) =
* Update: Added AVIF in valid mime types. 
* Info: This plugin is alive thanks to you! So if you have one minute, please give it a good review [here](https://wordpress.org/support/plugin/wplr-sync/reviews/?rate=5#new-post). Thank you :)

= 6.4.1 (2024/08/24) =
* Fix: Minor security issues related to wplrsync_link and wplrsync_unlink.
* Update: Removed dependency from WordPress scripts.
* Update: Lighter common libs.

= 6.4.0 (2024/06/03) =
* Update: Code cleaning and optimization.
* Update: Latest NekoUI and common libs.

= 6.3.3 (2024/04/27) =
* Update: Consolidated multiple useSWR hooks into a single useSWR for fetching media, improving efficiency and maintainability.
* Update: Applied security patches to enhance system protection.

= 6.3.1 (2023/12/25) =
* Add: Integration with Meow Collections (in the Meow Gallery).

= 6.3.0 (2023/12/15) =
* Fix: Issues with some modals in the UI.

= 6.2.8 (2023/09/08) =
* Fix: Compatibility with PHP 8.2.8.

= 6.2.7 (2023/08/29) =
* Fix: Avoid turning off the REST API Cache in Litespeed.

= 6.2.6 (2023/07/21) =
* Fix: Vulnerability: [Patchstack](https://patchstack.com/database/vulnerability/wplr-sync/wordpress-photo-engine-plugin-6-2-5-insecure-direct-object-references-idor).
* Fix: Consolidate screen was not working properly.

= 6.2.5 (2023/07/08) =
* Fix: There were some UI issues with checkboxes.

= 6.2.4 (2023/04/23) =
* Update: Fresh UI framework.
* Fix: Media entries were limited to 1,000 through the API.

= 6.2.3 (2023/01/15) =
* Fix: The Meow Apps Dashboard was blank.

= 6.2.2 (2022/09/11) =
* Add: The function get_media_from_collection() now also handles 'limit' and 'offset' parameters.

= 6.2.1 (2022/08/16) =
* Add: The archive page for the Keywords taxonomy now return the related media items.

= 6.2.0 (2022/07/24) =
* Fix: Could not re-order the content in a collection.

= 6.1.9 (2022/06/09) =
* Update: The token can be generated without using the Generate Token button (which seems not to work in rare case), but simply by clicking on Update Profile.
* Fix: There was an issue in the Organizer (the paging in the collections was not working).

= 6.1.7 (2022/02/20) =
* Fix: Crash if apply_collection_order_by was applied to a collection without anything in it.
* Update: Photos are selectable with CTRL instead of SHIFT. Shift is for choosing a range of photos instead.
* Add: Added the delete button to the header when selecting the folder.

= 6.1.5 (2021/12/07) =
* Fix: Little issues in the admin dashboard.

= 6.1.3 (2021/10/22) =
* Fix: The browser attachs better to the modals.
* Fix: Increased security.
* Update: Bigger thumbnails for consolidation.

= 6.1.1 =
* Add: When Taken Date is used, we can still override the Upload Folder to use the Upload Date (new option).
* Update: Refreshed common admin, enhanced UI.

= 6.1.0 =
* Fix: The Total Sync module was not working.

= 6.0.9 =
* Fix: The photos will be now uploaded to a YYYY/MM folder that is relative to their Taken Date (if the option is checked in the settings).
* Update: Tiny enhancements to the UI.

= 6.0.8 =
* Fix: The browser on the left side was breaking in some rare cases.
* Fix: Removed a comma that causes issues for a very specific version of PHP.

= 6.0.7 =
* For those who are having issues with LR collections not showing up in the Organizer, please use the 'Clean DB' button in 'Extensions & Debug'.

= 6.0.6 =
* The order wasn't applied properly in the Organizer (remember, order is done only through LR for this).
* Removed a few issues related to the DB and the way I was using arrays.
* The way the browser is added is now different, might be cleaner this way.

= 6.0.5 =
* Update: Lot of small (but important) fixes and enhancements.

= 6.0.3 =
* Update: Photo Engine is now using the Neko UI, a much better new UI. 
* Update: Everything has been moved under the Meow Apps menu.
* Add: Media Organizer and Media Browser (this is beta, please try it).
* Fix: The Avoid Double Processing wasn't working the first sync, only after that.
* Update: When a resync is being made on a media, the internal version is also updated. That is used by the Perfect Images plugin, and allows refreshing CDNs.
* Added an option to disable the Image Treshold (highly recommended to check it).

= 5.1.8 =
* Update: Optimized the files and the plugin is now a bit lighter.
* Fix: Simplified an expression, fixed a few variables which are used for debugging.
* Info: There has been no (discovered) bugs in WP/LR Sync for the past 4 months, so... champagne!

= 5.1.7 =
* Add: Filters for checking file existence.
* Update: Admin enhancements.

= 5.1.6 =
* Fix: "Avoid Double Processing" wasn't working well, now it should be better (but still beta, so use with caution).
* Fix: Remove some useless logging.

= 5.1.5 =
* Add: New parameter for shortcode: wplr-keywords-and (all the keywords need to be present the media entry to be displayed).
* Update: Avoid removing quotes from the keywords.
* Update: Removing keywords, folders or collections through the Galleries menu in now more convenient.

= 5.1.4 =
* Add: wplr_calculate_pHash filter, for the developers interested in adding their own way to match photos using Total Sync.
* Fix: The variable used for the version number wasn't properly named.

= 5.1.3 =
* Update: i18n fixes.

= 5.1.2 =
* Update: Admin refreshed to 2.4.
* Add: When the gallery icon is clicked in the Media Library Explorer, the Gallery shortcode is displayed.

= 5.1.0 =
* Fix: Fixed the Explorer which could interfere with some page builders.
* Add: The constant DOING_WPLR_REQUEST is now set when the WP/LR Sync API is running (for developers). 

= 5.0.8 =
* Fix: The warning message about WP/LR Sync was reset by caching/cleaning solutions.
* Add: Detect potential issues with NinjaFirewall.

= 5.0.6 =
* Add: New 'Catch Errors' option. Can be useful if you are not able to fix the errors (coming from other plugins or your theme) happening on your install, but really would like to be able to use WP/LR Sync anyway.

= 5.0.3 =
* Fix: Use the PHP function to move uploaded files, that helps in some cases.
* Fix: Better handling of errors.
* Add: New 'Troubleshooting' section in the WP/LR Sync Settings, to detect potential issues.

= 5.0.2 =
* Fix: Better handling for the ones using the Theme Assistant plugin.
* Info: Have a look below at the changes of the Version 5.0.0 if you didn't update to the 5+ version yet.

= 5.0.0 =
* Info: There is a huge update! The plugin on the Lightroom needs to be also updated. Please check this page: [Update to WP/LR Sync 5.0](https://meowapps.com/wplr-sync-5-0/).
* Add: New protocol, and the old XML/RPC and REST ones were removed.
* Add: Better order options through the API.
* Update: Explorer enhanced, many will love it.
* Update: Login through token only, no more user/password to avoid security issues and to simplify the process.

= 4.4.9 =
* Fix: Rare case. The mime_content_type was set to nothing for PHP versions prior to 5.3.0 (and without the PECL extension).

= 4.4.8 =
* Fix: If the function mime_content_type does not exist on the user install, gets the mime type depending on the file extension.
* Update: The re-order process was rewritten and is now much, much faster than before. The Theme Assistant also needs to be updated if you are using it.

= 4.4.4 =
* Add: Explorer mode has been added. It is added dynamically to the Media Library and the Add or Edit Media modals in the Editor. It's lighter than RML but it doesn't replace it in terms of features. It will be kept simple and straightforward. Please check the Settings.

= 4.4.0 =
* Info: This is a big update. We are working hard on WP/LR Sync to take it to the next level. Faster, easier to use, with better extensions. Please review the plugin if you like it, that motivates us a lot :)
* Info: The Post Types extension and the RML extension has been deprecated, and moved to the WordPress repository with better names. If you were using those, follow the procedure that will be displayed in your WordPress admin.
* Update: Better layout in the admin, re-structrured the menus.
* Update: Beter error handling.
* Fix: Mime type was always the same.

= 3.3.9 =
* Fix: Issue with re-sync for Description meta.
* Fix: Compatibility with PHP 7.2.

= 3.3.6 =
* Update: Just make sure that the RML extension loads with the latest version of RML (4.0.0).
* Info: For the last 10 months, the plugin had no bugs! I will be able to push new features now that everything is perfectly stable.

= 3.3.5 =
* Update: Better display of the root folder for Real Media Library.
* Update: If no Custom Order for Galleries, use the Media Upload Date.

= 3.3.4 =
* Fix: MLA couldn't update the ALT.
* Update: Post Types creates the collection again if it was deleted by mistake.
* Update: Better deletion process for collections and keywords in the admin.

= 3.3.1 =
* Fix: Make sure all the OB buffering are done by the end of the REST calls.

= 3.2.9 =
* Fix: Delete in the Collections & Tags shouldn't redirect to the Debugging page.
* Add: We can see which post is synchronized through the Post Types extension.
* Fix: Don't use OB if there is already a OB process.
* Add: More logging when needed.

= 3.2.6 =
* Add: The attributes (collections, keywords) for the [gallery] shortcode supports the standard WP shortcode as well. You can now keep everything updated so easily! Please also have a look at the Meow Gallery plugin.
* Fix: Tiny fix in the Post Types Extension.
* Fix: Custom Order for WP Gallery.

= 3.2.2 =
* Add: Collections & Keywords screen in the menu. Please check it and tell me what you think about it.
* Add: Shortcode [gallery collections="1,2"] and [gallery keywords="1,2"] to display your images based on your collections or keywords easily. This also requires the Meow Gallery plugin.
* Add: Advanced error catching to avoid warnings and errors from other plugins to impact WP/LR Sync processes.
* Fix: Order in Galleries.

= 3.1.3 =
* Add: Plugin is now translatable.

= 3.1.0 =
* Add: Keywords Hierarchy available in the Debugging Tools.
* Fix: Better handling of the keywords from Lightroom to WordPress.
* Info: Check for the latest LR Plugin 3.0.8 in the Meow Apps Store (https://store.meowapps.com/), keywords management has been improved.

= 3.0.4 =
* Update: Plugin now catches external PHP Errors (in other plugins) and send the debug to the LR Plugin. That should help a lot for debugging in case of issue.
* Info: There are big changes about the licensing system and the new Meow Apps Store, please read this: https://meowapps.com/wplr-sync-3-store/. Don't hesitate to comment on that article with any thoughts you might have. Working hard to make everything more than perfect, for now and the future :)

= 3.0.0 =
* Add: Order photos within a collection.
* Fix: HTTP Bearer for Public API and API on by default.
* Fix: Better handling for manually deleted media in WP. Trash is now also disabled if media is synced.
* Info: There is now an iPhone app for WP/LR Sync! Look for WP/LR in your Apple Store.

= 2.7.3 =
* Update: New version of RML and the extension.
* Fix: Manual link/unlink issue.
* Fix: There was an issue with the folders / collections when shown as filter in the Media Library.
* Info: I need your help. I need to advertise and communicate about the plugin a bit more so if you know any blog, magazine or website that might be interested in talking about it, please let me know (https://meowapps.com/contact/). Thank you always for your support :)

= 2.6.9 =
* Update: Nicer UI, include the Meow Apps admin, let's see how it goes. It any issue, please contact me.
* Fix: Little bug in the RML Extension.
* Fix: The Extension for Real Media Library now works with the latest version of that plugin (version 2.8, thanks to Matthias). You can check about his plugin here: https://codecanyon.net/item/wp-real-media-library-media-categories-folders/13155134?ref=TigrouMeow.

= 2.6.6 =
* Add: Media Tools can list ignored photos in order to link them.
* Add: Warnings in the case a certain option in W3 Total Cache is used (it does not work with WP/LR Sync).
* Add: Additional features for developers (more to come soon).
* Fix: Galleries weren't always updated by the Post Types extension if options were used in the shortcode.
* Fix: In the admin, a CSS file couldn't be found. Wasn't a big issue, but still, it was not clean.
* Fix: Extension for RML will not be loaded if the RML plugin is not active.
* Add: In the Debugging Tools > Hierarchy, it is now possible to remove collections/folders. Useful when LR creates a collection/folder on the server and that the reply is not handled (in case of slow or cut connection).

= 2.5.8 =
* Fix: Broken pages in the admin of WP/LR Sync after code cleaning.
* Fix: Avoid to break if the EXIF within the images is broken.
* Update: Full support for Real Media Library. Please check the Extensions menu in WP/LR Sync.
* Update: Removed the donation button in the screens.
* Add: Post Type, mode added. "Array in Post Meta" let you use a post meta to update your galleries (now handle many more themes and plugins).
* Fix: Post Type, handle removed Featured Image nicely by replacing it by an available one automatically.
* Add: Options for theme developers using Post Types.
* Add: Extension for Real Media Library. This extension is in beta.
* Fix: Little issue with remove_taxonomy_from_posttype in Post Types.

= 2.5.0 =
* Add: Options for adding Keywords in the Media Library and sync them automatically.
* Update: Display a message to the user if the Permalinks are not set (required for the REST protocol).
* Fix: The Total Sync was failing after the new REST protocol was added. Should be okay now.
* Update: Option "Accents in Filename" renamed to "Skip Sanitization" and the description was updated.
* Add: New Option 'Media Date' to use the photo taken date instead of the upload date in the Media Library.
* Add: New options 'Accents in Filename' to enable accents in filenames. By default, accents will be replaced by non-accented characters.
* Add: Supports the REST protocol. Now the Lightroom plugin will have the choice to use either XML/RPC or REST as a protocol, which might remove a lot of XML/RPC related issues. You will need to use the newest version of the LR plugin, not available publicly yet (but soon).

= 2.3.8 =
* Update: Change the way a few things were called, and the description.
* Fix: Post type extension was always created new post with the default category (called Uncategorized by default).
* Fix: Unlink and Delete links in the Media Tools weren't working.
* Add: Extension "Post Types" now supports two new options. First, is that keywords can be linked to a taxonomy. Second is that a post-type can be created either as publish or draft.
* Update: Extension "Post Types" has more options. Now can sync with existing post in your post-type and term in your taxonomy. For example, you can link your LR collection to your already existing album/collection on WordPress. Same with the categories, folders, etc. I probably need to write a tutorial about this one day but for advanced users it will be easy to figure out.

= 2.3.0 =
* Added: New Extension! Called Post Types. Handle custom Post Types and Taxonomies (to support more themes and plugins). Plase try it out to sync your Collections and Folders/Sets. I write a little about this news here: https://meowapps.com/wplr-sync-post-types-extension/.
* Fix: If plugin can't get the maximum size for http uploads, return a big value anyway (to avoid blocking users).
* Fix: Logger Extension was failing on PHP 7.0.
* Update: Headers now compliant with WP 4.4.
* Fix: Keywords count for the Basic Posts extension now updates itself.
* Fix: Basic Posts extension was still the old one for some reason.

= 2.2.0 =
* Add: Support for hierarchical keywords.
* Fix: The Clean Database button was not working well on WP MultiSite.
* Update: Basic Posts extension is not so basic anymore. Added categories (based on LR collections) and keywords.
* Info: Basic Posts is becoming a very good example of the power of those extensions. I will improve depending on your requests :)
* Info: A new version of the plugin for LR is required (2.2.0) for this new hierarchical keywords support. Check https://meowapps.com.
* Update: WP 4.3 support.
* Info: There is a new version of the plugin for Lightroom since today (2015/08/20).
* Info: Please update it to avoid the NOT_MEOWAPPS issue to appear in LR (which is fixed by log-off + log-on).

= 2.0.0 =
* Add: Collections support.
* Add: Tags support for media.
* Add: Many actions for other plugins and extensions to use.
* Add: 3 internal extensions added: Basic Posts, Basic Galleries and Logging.
* Update: Bigger menu for WP/LR Sync, everything has been re-organized.
* Update: Debugging Tools for WP/LR Sync now accessible through an option.
* Fix: Multisite is now supported.
* Info: That's a BIG update. Everything has been tested. You can update it already. The plugin for Lightroom will follow. Many information are available on https://meowapps.com/wplr-sync. Also just wrote a post about this news, please read it here: https://meowapps.com/wplr-sync-2-0/. Thank you!

= 1.3.6 =
* Fix: Issue with rights on uploaded files.
* Fix: Multilanguage support issue with un-links detection (not a major bug).
* Change: The temporary directory has been changed to avoid issues.
* Fix: Presync support for HVVM.
* Fix: Handle broken databases nicely and period of time when the plugin is turned off (and changes are made).
* Fix: Plugin keeps its own DB table clean.
* Add: Presync. PHP settings are sent to LR to prevent errors.
* Add: Update the empty WP metadata with the LR data.
* Fix: Change on how temporary files are created (to support HHVM).

= 1.2.0 =
* Add: Additional features to support WPML Media.
* Update: Switch Photos module enabled in LR.
* Add: Compatibility with WPML Media (translation plugin for the media images).
* Info: WPML Media needs to change something on their side for full support. Please check this post: https://meowapps.com/wpml-media-and-wplr-sync/.
* Add: Ignore button.
* Add: Post attachment information and showing the titles of post and media when hovering the links.
* Fix: When linking a media, the page doesn't scroll up annoyingly to the top anymore.
* Add: Handlers of new module in the LR plugin (module to switch photos).
* Info: In preparation of the future release of the LR plugin (1.2).

= 0.8 =
* Fix: Duplicate files are now all deleted on WP when the LR photo is removed (against only the first one before).
* Info: Minor and major number of the most current version between the WP and LR plugins will always match from now.
* Add: Undo function available.
* Fix: Many WP images linked to same LR image? They now all update, instead of only the first one previously.
* Fix: Title was not being updated properly during sync.
* Add: Dashboard for WPLR.
* Update: Better sync/link management through the Media Manager.
* Add: Handles metadata.
* Fix: XML/RPC Sync.

= 0.1 =
* First release.

== Screenshots ==

1. Photo Engine Publish Service in Lightroom
2. Synchronized files in the Media Library
2. Publish Service Settings
3. Total Synchronization Module
4. Advanced Tab in Total Synchronization
