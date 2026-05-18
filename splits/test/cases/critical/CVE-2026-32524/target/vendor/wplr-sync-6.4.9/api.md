Those function could be easily used by themes or plugins willing to integrate Photo Engine.

# FOR A GALLERY PLUGINS

`global $wplr;`

## Get Collection
`get_collection( $id )`
`get_collection_from_slug( $slug )`

## Get Folder
`get_folder( $id )`
`get_folder_from_slug( $slug )`

## Get Keywords (from media)
`get_tags_from_media( $mediaId )`

## Get Media (for keyword)
`get_media_from_tag( $id )`

## Get Media (in a collection)
`get_media_from_collection( $id )`

## Get Media (in a collection) as a Gallery (with more information for UI)
`get_gallery( $id )`

All the data returned should be enough for a theme or a gallery plugin.

## Get Collections (for a media)
`get_collections_from_media( $mediaId )`

## Get Collections (in a folder)
`get_collections_from_folder( $folderId )`

If there is no folderId, the collections in root will be returned.

## Get Folders (in a folder)
`get_folders_from_folder( $folderId )`

If there is no folderId, the folders in root will be returned.

## Get Hierarchy of Folders/Collections
`get_hierarchy()`
`get_hierarchy( $parent = null, $level = 0, $source = 'lr' )`

## Get Hierarchy of Keywords:
`get_keywords_hierarchy()`

# OTHERS

## Create a Folder/Collection
`create_collection( $source = 'lr', $type = 'collection', $name = '', $lr_col_id = null, $parent_folder = null )`
- $lr_col_id: The external ID used by the editor or other system (does not matter if the source is WP).
- $parent_folder: The WP ID of the parent folder (if any).

## Update a Folder/Collection (only name for now)
`update_collection( $wp_col_id, $name = '' )`
- $wp_col_id: The internal ID used for this collection.
- $name: The name (or title) for this collection.

## Move a Folder/Collection
`move_collection( $wp_col_id, $parent_folder = null )`
- $wp_col_id: The internal ID used for this collection.
- $parent_folder: The WP ID of the parent folder (if any, otherwise it goes back to root).

## Add Media to Collection
`add_media_to_collection( $wp_id, $wp_col_id, $sort = 0 )`
- $wp_id: The internal ID used for this media.
- $wp_col_id: The internal ID used for this collection.
- $sort: (I will document this later).

## Remove Media to Collection
`remove_media_from_collection( $wp_id, $wp_col_id )`
- $wp_id: The internal ID used for this media.
- $wp_col_id: The internal ID used for this collection.

# Basic WordPress Actions

## Before media is synchronize
`wplr_presync_media`
- $lrinfo: Info shared by Lightroom
- $tmp_path: Temporary filepath

## Media was added
`wplr_add_media`
- $wp_id: The internal ID which was replaced.

## Media was updated
`wplr_update_media`
- $wp_id: The internal ID which was replaced.
- $gallery_ids: The collections in which this media can be found.

## Media was synchronized
`wplr_sync_media`
- $sync: Sync information. 

# Advanced WordPress Actions

There are many...