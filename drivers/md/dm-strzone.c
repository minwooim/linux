#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/bio.h>
#include <linux/device-mapper.h>

#define KB	(1024)

/*
 * Must be power-of-2 and larger than 4KB.
 */
static unsigned int chunk_size = 128 * KB;
module_param(chunk_size, uint, 0644);

enum {
	DM_STRZONE_GREEDY,
};

static int mode;
module_param(mode, int, 0644);

struct strzone_pmap {
	u64 slba;
	u32 nlb;
};

typedef struct strzone_pmap strzone_extent;

struct strzone_lmap {
	u64 slba;
	u32 nlb;
	struct strzone_pmap *pmap;
	int nr_pmaps;

	struct rb_node node;
};

struct strzone_metadata {
	struct xarray zones;

	struct list_head free_zones_list;
	struct list_head partial_zones_list;
	struct list_head full_zones_list;

	struct rb_root lmap_root;
};

struct strzone_target {
        struct dm_dev *dev;
        sector_t start;

	unsigned int logical_block_size;
	unsigned int chunk_size_blocks;

	/*
	 * ZNS-specific parameters
	 */
	sector_t zone_size;
	int zone_size_shift;
	sector_t zone_capacity;
	unsigned int nr_zones;

	struct bio_set bio_set;

	struct strzone_metadata *metadata;
};

struct strzone_io {
	struct strzone_target *szt;
	atomic_t io_count;
	struct bio *orig_bio;

	unsigned int stripe_count;
	struct bio **clone;

	struct strzone_lmap *lmap;
};

struct strzone_tio {
	struct strzone_io *io;
	struct bio clone;
};
#define DM_STRZONE_TIO_BIO_OFFSET \
	(offsetof(struct strzone_tio, clone))

struct strzone_zone {
	struct strzone_target *szt;
	struct list_head list;

	unsigned int id;
	u64 slba;
	u64 wp;
};

static inline const char *bio_op_name(struct bio *bio)
{
	switch (bio_op(bio)) {
	case REQ_OP_READ:
		return "READ";
	case REQ_OP_WRITE:
		return "WRITE";
	case REQ_OP_ZONE_APPEND:
		return "ZONE APPEND";
	default:
		return "UNKNOWN";
	}
}

static inline u64 zone_to_lba(struct strzone_zone *zone)
{
	struct strzone_target *szt = zone->szt;

	return (zone->id * to_bytes(szt->zone_size)) >> szt->zone_size_shift;
}

static inline u64 sector_to_lba(struct strzone_target *szt, sector_t sector)
{
	return (sector << SECTOR_SHIFT) >> ilog2(szt->logical_block_size);
}

static inline u64 lba_to_sector(struct strzone_target *szt, u64 lba)
{
	return to_sector(lba << ilog2(szt->logical_block_size));
}

static inline u64 sector_to_nlb(struct strzone_target *szt, sector_t sector)
{
	return DIV_ROUND_UP(sector << SECTOR_SHIFT, szt->logical_block_size);
}

static inline sector_t zone_remaining_sectors(struct strzone_zone *zone)
{
	struct strzone_target *szt = zone->szt;
	sector_t used = lba_to_sector(szt, zone->wp) -
		lba_to_sector(szt, zone->slba);

	return szt->zone_capacity - used;
}

static bool strzone_lmap_insert(struct strzone_metadata *meta,
		struct strzone_lmap *lmap)
{
	struct rb_root *root = &meta->lmap_root;
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	/* Figure out where to put new node */
	while (*new) {
		struct strzone_lmap *this = container_of(*new, struct strzone_lmap, node);
		int result = lmap->slba - this->slba;

		parent = *new;
		if (result < 0)
		      new = &((*new)->rb_left);
		else if (result > 0)
		      new = &((*new)->rb_right);
		else
		      return false;
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&lmap->node, parent, new);
	rb_insert_color(&lmap->node, root);

	pr_info("dm-strzone: insert: lmap->slba=%lld, lmap->nlb=%d\n",
			lmap->slba, lmap->nlb);

	return true;
}

struct strzone_lmap *strzone_lmap_search(struct rb_root *root, u64 slba)
{
      struct rb_node *node = root->rb_node;

      while (node) {
              struct strzone_lmap *lmap = container_of(node,
			      struct strzone_lmap, node);
              int result = slba - lmap->slba;

              if (result < 0)
                      node = node->rb_left;
              else if (result > 0) {
		      if (result < lmap->nlb)
			      return lmap;
                      node = node->rb_right;
	      } else
                      return lmap;
      }

      return NULL;
}

static void strzone_lmap_dump(struct strzone_metadata *meta)
{
	struct rb_node *node;

	for (node = rb_first(&meta->lmap_root); node; node = rb_next(node)) {
		struct strzone_lmap *lmap =
			rb_entry(node, struct strzone_lmap, node);
		pr_info("\tslba=0x%llx\n", lmap->slba);
	}
	pr_info("\n");
}

static struct strzone_zone *__strzone_alloc_free_zone(struct strzone_metadata *meta)
{
	struct strzone_zone *zone;

	zone = list_first_entry_or_null(&meta->free_zones_list,
			struct strzone_zone, list);
	if (zone)
		list_del_init(&zone->list);

	return zone;
}

static struct strzone_zone *__strzone_alloc_partial_zone(struct strzone_metadata *meta)
{
	struct strzone_zone *zone;

	zone = list_first_entry_or_null(&meta->partial_zones_list,
			struct strzone_zone, list);
	if (zone)
		list_del_init(&zone->list);

	return zone;
}

static struct strzone_zone *__strzone_alloc_zone_greedy(struct strzone_metadata *meta)
{
	struct strzone_zone *zone;

	zone = __strzone_alloc_partial_zone(meta);
	if (!zone)
		return __strzone_alloc_free_zone(meta);

	return zone;
}

static struct strzone_zone *strzone_alloc_zone(struct strzone_metadata *meta)
{
	switch (mode) {
	case DM_STRZONE_GREEDY:
		return __strzone_alloc_zone_greedy(meta);
	default:
		BUG();
	}
}

static void strzone_done_zone(struct strzone_zone *zone, u32 nlb)
{
	struct strzone_metadata *meta = zone->szt->metadata;

	zone->wp += nlb;

	if (zone_remaining_sectors(zone) < to_sector(chunk_size))
		list_add_tail(&zone->list, &meta->full_zones_list);
	else
		list_add_tail(&zone->list, &meta->partial_zones_list);
}

static inline struct strzone_tio *clone_to_tio(struct bio *clone)
{
	return container_of(clone, struct strzone_tio, clone);
}

static void strzone_bio_endio(struct strzone_io *io)
{
	struct bio *bio = io->orig_bio;
	int i;

	for (i = 0; i < io->stripe_count; i++)
		bio_put(io->clone[i]);

	bio_endio(bio);
	pr_info("dm-strzone: %s: bio_endio(%p): op=%s, bi_sector=%lld(LBA %lld), bi_size=%u bytes(NLB %lld)\n",
			io->szt->dev->name, bio, bio_op_name(bio),
			bio->bi_iter.bi_sector,
			sector_to_lba(io->szt, bio->bi_iter.bi_sector),
			bio->bi_iter.bi_size,
			sector_to_lba(io->szt, to_sector(bio->bi_iter.bi_size)));
}

static void strzone_dec_pending(struct strzone_io *io)
{
	if (atomic_dec_and_test(&io->io_count))
		strzone_bio_endio(io);
}

static void strzone_clone_endio(struct bio *bio)
{
	struct strzone_tio *tio = container_of(bio, struct strzone_tio, clone);
	struct strzone_io *io = tio->io;
	struct strzone_target *szt = io->szt;
	struct strzone_zone *zone = bio->bi_private;

	pr_info("dm-strzone: %s: \tclone_endio(%p): bio(%p), op=%s, bi_sector=%lld(LBA %lld), bi_size=%u bytes(NLB %lld)\n",
			szt->dev->name, bio, io->orig_bio, bio_op_name(bio),
			bio->bi_iter.bi_sector,
			sector_to_lba(szt, bio->bi_iter.bi_sector),
			bio->bi_iter.bi_size,
			sector_to_lba(szt, to_sector(bio->bi_iter.bi_size)));

	if (zone && bio->bi_status == BLK_STS_OK)
		strzone_done_zone(zone, sector_to_nlb(szt, bio_sectors(bio)));
	strzone_dec_pending(io);
}

static void strzone_submit_bio_remap(struct bio *clone)
{
	struct strzone_tio *tio = container_of(clone, struct strzone_tio, clone);
	struct strzone_io *io = tio->io;
	struct strzone_target *szt = io->szt;

	pr_info("dm-strzone: %s: \tsubmit_clone(%p): bio(%p), op=%s, bi_sector=%lld(LBA %lld), bi_size=%u bytes(NLB %lld)\n",
			szt->dev->name, clone, io->orig_bio, bio_op_name(clone),
			clone->bi_iter.bi_sector,
			sector_to_lba(szt, clone->bi_iter.bi_sector),
			clone->bi_iter.bi_size,
			sector_to_lba(szt, to_sector(clone->bi_iter.bi_size)));

	submit_bio_noacct(clone);
}

static void __strzone_alloc_io_write(struct bio *bio, struct strzone_io *io)
{
	struct strzone_target *szt = io->szt;
	const sector_t chunk_sectors = chunk_size >> SECTOR_SHIFT;
	unsigned int size = bio->bi_iter.bi_size;
	unsigned int stripe_count = DIV_ROUND_UP(size, chunk_size);
	sector_t remaining = to_sector(size);
	struct bio *orig_bio;
	int i;

	/*
	 * Clone the original bio to split it to multiple clone bios.
	 */
	orig_bio = bio_alloc_clone(NULL, bio, GFP_NOIO, &szt->bio_set);

	io->stripe_count = stripe_count;
	atomic_set(&io->io_count, io->stripe_count);
	io->clone = kmalloc(sizeof(struct bio *) * io->stripe_count,
			GFP_KERNEL);

	for (i = 0; i < io->stripe_count; i++) {
		struct strzone_tio *tio;
		struct bio *clone;

		clone = bio_alloc_clone(NULL, orig_bio, GFP_NOIO,
				&szt->bio_set);
		clone->bi_end_io = strzone_clone_endio;
		clone->bi_iter.bi_size = (remaining < chunk_sectors) ?
			to_bytes(remaining) : to_bytes(chunk_sectors);

		bio_set_dev(clone, szt->dev->bdev);

		tio = container_of(clone, struct strzone_tio, clone);
		tio->io = io;
		io->clone[i] = clone;

		remaining -= to_sector(clone->bi_iter.bi_size);
		if (remaining)
			bio_advance(orig_bio, chunk_sectors << SECTOR_SHIFT);
	}
}

static void __strzone_alloc_io_read(struct strzone_io *io,
		struct xarray *extents, unsigned int nr_extents)
{
	struct strzone_target *szt = io->szt;
	struct bio *bio = io->orig_bio;
	struct bio *orig_bio;
	sector_t remaining = bio_sectors(bio);
	unsigned long idx;
	strzone_extent *extent;

	orig_bio = bio_alloc_clone(NULL, bio, GFP_NOIO, &io->szt->bio_set);

	io->stripe_count = nr_extents;
	atomic_set(&io->io_count, io->stripe_count);
	io->clone = kmalloc(sizeof(struct bio *) * io->stripe_count,
			GFP_KERNEL);

	xa_for_each(extents, idx, extent) {
		struct strzone_tio *tio;
		struct bio *clone;

		clone = bio_alloc_clone(NULL, orig_bio, GFP_NOIO,
				&szt->bio_set);
		clone->bi_end_io = strzone_clone_endio;
		clone->bi_iter.bi_sector = lba_to_sector(szt, extent->slba);
		clone->bi_iter.bi_size =
			to_bytes(lba_to_sector(szt, extent->nlb));

		bio_set_dev(clone, szt->dev->bdev);

		tio = container_of(clone, struct strzone_tio, clone);
		tio->io = io;
		io->clone[idx] = clone;

		remaining -= to_sector(clone->bi_iter.bi_size);
		if (remaining)
			bio_advance(orig_bio, clone->bi_iter.bi_size);

	}
}

static struct strzone_io *strzone_alloc_io(struct strzone_target *szt,
		struct bio *bio)
{
	struct strzone_io *io;

	io = kzalloc(sizeof(struct strzone_io), GFP_KERNEL);
	io->szt = szt;
	io->orig_bio = bio;

	if (bio_op(bio) == REQ_OP_WRITE)
		__strzone_alloc_io_write(bio, io);

	return io;
}

static int strzone_submit_bios(struct strzone_io *io)
{
	int i;

	/*
	 * `stripe_count == 0` means no mapping found.  system-udevd reads at
	 * the first time.
	 */
	if (!io->stripe_count) {
		bio_set_dev(io->orig_bio, io->szt->dev->bdev);
		submit_bio(io->orig_bio);
		return DM_MAPIO_SUBMITTED;
	}

	for (i = 0; i < io->stripe_count; i++)
		strzone_submit_bio_remap(io->clone[i]);

	return DM_MAPIO_SUBMITTED;
}

static struct strzone_lmap *strzone_remap_write(struct strzone_io *io)
{
	struct strzone_target *szt = io->szt;
	u64 slba = sector_to_lba(szt, io->orig_bio->bi_iter.bi_sector);
	u32 nlb = sector_to_nlb(szt, bio_sectors(io->orig_bio));
	struct strzone_lmap *lmap;
	int i;

	lmap = kmalloc(sizeof(struct strzone_lmap), GFP_KERNEL);
	if (!lmap)
		return NULL;

	lmap->slba = slba;
	lmap->nlb = nlb;
	lmap->nr_pmaps = io->stripe_count;
	lmap->pmap = kmalloc(sizeof(struct strzone_pmap) * lmap->nr_pmaps,
			GFP_KERNEL);
	if (!lmap->pmap) {
		kfree(lmap);
		return NULL;
	}

	for (i = 0; i < lmap->nr_pmaps; i++) {
		struct bio *clone = io->clone[i];
		struct strzone_zone *zone = strzone_alloc_zone(szt->metadata);
		BUG_ON(!zone);

		clone->bi_iter.bi_sector = lba_to_sector(szt, zone->wp);
		clone->bi_private = zone;
		lmap->pmap[i].slba = zone->wp;
		lmap->pmap[i].nlb = sector_to_nlb(szt, bio_sectors(clone));
	}

	return lmap;
}

static int strzone_get_extents(struct strzone_target *szt, u64 slba, u32 nlb,
		struct xarray *extents)
{
	u64 lba = slba;
	u32 remaining = nlb;
	struct strzone_lmap *lmap;
	int nr_extents = 0;
	strzone_extent *extent;
	unsigned long idx;
	struct strzone_pmap *pmap;

	while (remaining) {
		int chunk_idx;
		int chunk_blocks;

		lmap = strzone_lmap_search(&szt->metadata->lmap_root, lba);
		if (!lmap)
			goto nomap;

		chunk_idx = (lba - lmap->slba) / szt->chunk_size_blocks;
		chunk_blocks = (lba - lmap->slba) % szt->chunk_size_blocks;

		pmap = &lmap->pmap[chunk_idx++];
		extent = kmalloc(sizeof(strzone_extent), GFP_KERNEL);
		extent->slba = pmap->slba + chunk_blocks;
		extent->nlb = (remaining > pmap->nlb - chunk_blocks) ?
			pmap->nlb - chunk_blocks : remaining;
		remaining -= extent->nlb;
		lba += extent->nlb;
		if (xa_insert(extents, nr_extents++, extent, GFP_KERNEL))
			goto nomap;

		while (remaining && chunk_idx < lmap->nr_pmaps) {
			extent = kmalloc(sizeof(strzone_extent), GFP_KERNEL);
			extent->slba = lmap->pmap[chunk_idx].slba;
			extent->nlb = (remaining > lmap->pmap[chunk_idx].nlb) ?
				pmap->nlb : remaining;
			remaining -= extent->nlb;
			lba += extent->nlb;
			if (xa_insert(extents, nr_extents++, extent, GFP_KERNEL))
				goto nomap;

			chunk_idx++;
		}
	}

	return nr_extents;
nomap:
	xa_for_each(extents, idx, extent)
		kfree(extent);

	return 0;
}

static void strzone_remap_read(struct strzone_io *io)
{
	struct strzone_target *szt = io->szt;
	u64 slba = sector_to_lba(szt, io->orig_bio->bi_iter.bi_sector);
	u32 nlb = sector_to_nlb(szt, bio_sectors(io->orig_bio));
	int nr_extents;
	struct xarray extents;

	xa_init(&extents);

	nr_extents = strzone_get_extents(szt, slba, nlb, &extents);
	if (!nr_extents) {
		io->stripe_count = 0;
		xa_destroy(&extents);
		return;
	}

	__strzone_alloc_io_read(io, &extents, nr_extents);
	xa_destroy(&extents);
}

static void strzone_remap(struct strzone_io *io)
{
	struct strzone_target *szt = io->szt;

	if (bio_op(io->orig_bio) == REQ_OP_WRITE) {
		io->lmap = strzone_remap_write(io);
		strzone_lmap_insert(szt->metadata, io->lmap);
	} else if (bio_op(io->orig_bio) == REQ_OP_READ) {
		strzone_remap_read(io);
	}
}

static int strzone_submit(struct strzone_target *szt, struct bio *bio)
{
	struct strzone_io *io = strzone_alloc_io(szt, bio);

	strzone_remap(io);
	return strzone_submit_bios(io);
}

static int strzone_map(struct dm_target *ti, struct bio *bio)
{
        struct strzone_target *szt = (struct strzone_target *) ti->private;

	pr_info("dm-strzone: %s: submit_bio(%p): op=%s, bi_sector=%lld(LBA %lld), bi_size=%d bytes(NLB %lld)\n",
			szt->dev->name, bio, bio_op_name(bio),
			bio->bi_iter.bi_sector,
			sector_to_lba(szt, bio->bi_iter.bi_sector),
			bio->bi_iter.bi_size,
			sector_to_lba(szt, to_sector(bio->bi_iter.bi_size)));

	return strzone_submit(szt, bio);
}

static sector_t strzone_map_sector(struct dm_target *ti, sector_t bi_sector)
{
	struct strzone_target *szt = ti->private;

	return szt->start + dm_target_offset(ti, bi_sector);
}

static int strzone_report_zones(struct dm_target *ti,
		struct dm_report_zones_args *args, unsigned int nr_zones)
{
	struct strzone_target *szt  = ti->private;

	return dm_report_zones(szt->dev->bdev, szt->start,
			       strzone_map_sector(ti, args->next_sector),
			       args, nr_zones);
}

static int strzone_init_zone(struct blk_zone *blkz, unsigned int num,
		void *data)
{
	struct strzone_target *szt = data;
	struct strzone_metadata *meta = szt->metadata;
	struct strzone_zone *zone =
		kzalloc(sizeof(struct strzone_zone), GFP_KERNEL);

	if (!zone)
		return -ENOMEM;

	if (blkz->start != blkz->wp) {
		pr_info("dm-strzone: %s: Skip zone %u\n", szt->dev->name, num);
		return 0;
	}

	if (xa_insert(&meta->zones, num, zone, GFP_KERNEL)) {
		kfree(zone);
		return -EBUSY;
	}

	zone->id = num;
	zone->slba = (blkz->start << SECTOR_SHIFT) >>
		ilog2(szt->logical_block_size);
	zone->wp = (blkz->wp<< SECTOR_SHIFT) >> ilog2(szt->logical_block_size);
	zone->szt = szt;
	szt->nr_zones++;

	list_add_tail(&zone->list, &meta->free_zones_list);

	/*
	 * We assume that all the zone in a single ZNS device will have same
	 * zone capacity and we only support a single device to map.
	 */
	if (!szt->zone_capacity)
		szt->zone_capacity = blkz->capacity;

	return 0;
}

static int strzone_init_metadata(struct strzone_target *szt)
{
	struct strzone_metadata *meta;
	int ret;

	meta = kzalloc(sizeof(struct strzone_metadata), GFP_KERNEL);
	if (!meta)
		return -ENOMEM;
	meta->lmap_root = RB_ROOT;

	szt->metadata = meta;

	INIT_LIST_HEAD(&meta->free_zones_list);
	INIT_LIST_HEAD(&meta->partial_zones_list);
	INIT_LIST_HEAD(&meta->full_zones_list);

	ret = blkdev_report_zones(szt->dev->bdev, 0, BLK_ALL_ZONES,
			strzone_init_zone, szt);
	if (ret < 0) {
		pr_err("dm-strzone: Failed to report zones, error %d\n", ret);
		return ret;
	}

	pr_info("dm-strzone: %s: Initialized zones %u\n", szt->dev->name,
			szt->nr_zones);

	return 0;
}

static int strzone_ctr(struct dm_target *ti, unsigned int argc,
                char **argv)
{
        struct strzone_target *szt;
	unsigned int front_pad;

        szt = kzalloc(sizeof(struct strzone_target), GFP_KERNEL);
        if (!szt)
                return -ENOMEM;

        if (dm_get_device(ti, argv[0], dm_table_get_mode(ti->table),
                                &szt->dev)) {
                ti->error = "dm_strzone: Device lookup failed";
                goto out;
        }

        szt->start = (sector_t) 0;
	szt->logical_block_size = bdev_logical_block_size(szt->dev->bdev);
	szt->chunk_size_blocks = chunk_size / szt->logical_block_size;
	szt->zone_size = bdev_zone_sectors(szt->dev->bdev);
	if (!szt->zone_size) {
		pr_err("%s: Invalid chunk_sectors 0\n", "strzone");
		goto out;
	}
	szt->zone_size_shift = ilog2(szt->zone_size);


	/*
	 * zone capacity will be filled up in a report-zone stage.
	 */
	szt->zone_capacity = 0;
	front_pad = __alignof__(struct strzone_tio) + DM_STRZONE_TIO_BIO_OFFSET;
	if (bioset_init(&szt->bio_set, 8192, front_pad, 0))
		goto out;

        ti->private = szt;

	strzone_init_metadata(szt);

	pr_info("dm-strzone: %s: chunk_size=%u bytes, zone_size=%lld bytes, zone_capacity=%lld bytes\n", szt->dev->name, chunk_size,
			szt->zone_size << SECTOR_SHIFT,
			szt->zone_capacity << SECTOR_SHIFT);

        return 0;
out:
        kfree(szt);
        return -EINVAL;
}

static void strzone_dtr(struct dm_target *ti)
{
        struct strzone_target *szt = (struct strzone_target *) ti->private;

        dm_put_device(ti, szt->dev);
        kfree(szt);
}

static int strzone_iterate_devices(struct dm_target *ti,
				  iterate_devices_callout_fn fn, void *data)
{
	struct strzone_target *szt = ti->private;

	return fn(ti, szt->dev, szt->start, ti->len, data);
}

static struct target_type strzone = {
        .name = "strzone",
        .version = {1, 0, 0},
        .module = THIS_MODULE,
        .ctr = strzone_ctr,
        .dtr = strzone_dtr,
        .map = strzone_map,
	.features = DM_TARGET_ZONED_HM,
	.report_zones = strzone_report_zones,
	.iterate_devices = strzone_iterate_devices,
};

int __init dm_strzone_init(void)
{
        dm_register_target(&strzone);

        return 0;
}

void __exit dm_strzone_exit(void)
{
        dm_unregister_target(&strzone);
}

module_init(dm_strzone_init);
module_exit(dm_strzone_exit);

MODULE_LICENSE("GPL");
