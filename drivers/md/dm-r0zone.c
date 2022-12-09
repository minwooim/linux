#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/bio.h>
#include <linux/device-mapper.h>

#include "dm-core.h"

#define KB	(1024)

#define STRIPE_SIZE		(4)  /* Should be in power of 2 */
/* XXX: it should be retrived from the controller by an admin command */
#define OPTIMAL_WRITE_SIZE	(128 * KB)

/*
 * Must be power-of-2 and larger than 4KB.
 */
static unsigned int chunk_size = 128 * KB;
module_param(chunk_size, uint, 0644);

struct r0zone_metadata {
	struct xarray zones;

	struct list_head free_zones_list;
	struct list_head partial_zones_list;
	struct list_head full_zones_list;
};

struct r0zone_target {
        struct dm_dev *dev;
        sector_t start;

	unsigned int logical_block_size;
	unsigned int chunk_size_blocks;
	sector_t chunk_size_sectors;
	unsigned int nr_physical_zones;

	/*
	 * ZNS-specific parameters
	 */
	sector_t zone_size;
	int zone_size_shift;
	sector_t zone_capacity;
	unsigned int nr_zones;

	sector_t lzone_size;
	sector_t lzone_capacity;

	struct bio_set bio_set;

	struct r0zone_metadata *metadata;
};

struct r0zone_io {
	struct r0zone_target *szt;
	atomic_t io_count;
	struct bio *orig_bio;

	unsigned int stripe_count;
	struct bio **clone;
};

struct r0zone_tio {
	struct r0zone_io *io;
	struct bio clone;
};
#define DM_STRZONE_TIO_BIO_OFFSET \
	(offsetof(struct r0zone_tio, clone))

struct r0zone_zone {
	struct r0zone_target *szt;
	struct list_head list;

	unsigned int id;
	u64 slba;
	u64 wp;

	// based on sector size
	sector_t _start;
	sector_t _wp;
};

static inline sector_t l2p_sect(struct r0zone_target *target, sector_t sector)
{
	int lstart = sector / target->lzone_size;
	sector_t loffset = sector - (lstart * target->lzone_size);
	sector_t pstart = lstart * STRIPE_SIZE * target->zone_size;

	/*
	 * Example of chunk mapping for (STRIPE_SIZE = 4)
	 *
	 * |---------------------|	logical zone
	 *
	 * |---| |---| |---| |---|	physical zones
	 *  0     1     2     3		row=0
	 *   4     5     6     7	row=1
	 *    8     9     ...		row=2
	 * col=0 col=1 col=2 col=3
	 */
	// chunk id 는 구해올 수 있지만, 128k 로 나눠떨어지지 않을 수 있음.
	int chunk = loffset / target->chunk_size_sectors;
	sector_t remain = loffset % target->chunk_size_sectors;
	int row = chunk / STRIPE_SIZE;
	int col = chunk & (STRIPE_SIZE - 1);

	/*
	pr_err("sector=%lld / lstart=%lld, loffset=%lld, pstart=%lld(%lld), "
			"chunk=%d, remain=%lld, row=%d, col=%d\n",
			sector, lstart, loffset, pstart, pstart / target->zone_size,
			chunk,
			remain, row, col);
	*/

	return pstart + (col * target->zone_size) +
		(row * target->chunk_size_sectors) + remain;
}

static inline unsigned int sector_to_zone(struct r0zone_target *target,
		sector_t sector)
{
	return sector / target->zone_size;
}

static inline sector_t p2l_sect(struct r0zone_target *target, sector_t sector)
{
	sector_t lsize = target->zone_size * STRIPE_SIZE;
	sector_t pstart = sector / lsize * STRIPE_SIZE;

	int row = (sector - pstart) / target->chunk_size_sectors;
	int col = (sector - pstart) % target->chunk_size_sectors;

	return pstart + (row * STRIPE_SIZE + col) * target->chunk_size_sectors;
}

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

static inline u64 zone_to_lba(struct r0zone_zone *zone)
{
	struct r0zone_target *szt = zone->szt;

	return (zone->id * to_bytes(szt->zone_size)) >> szt->zone_size_shift;
}

static inline u64 sector_to_lba(struct r0zone_target *szt, sector_t sector)
{
	return (sector << SECTOR_SHIFT) >> ilog2(szt->logical_block_size);
}

static inline u64 lba_to_sector(struct r0zone_target *szt, u64 lba)
{
	return to_sector(lba << ilog2(szt->logical_block_size));
}

static inline u64 sector_to_nlb(struct r0zone_target *szt, sector_t sector)
{
	return DIV_ROUND_UP(sector << SECTOR_SHIFT, szt->logical_block_size);
}

static inline sector_t zone_remaining_sectors(struct r0zone_zone *zone)
{
	struct r0zone_target *szt = zone->szt;
	sector_t used = lba_to_sector(szt, zone->wp) -
		lba_to_sector(szt, zone->slba);

	return szt->zone_capacity - used;
}

static inline struct r0zone_tio *clone_to_tio(struct bio *clone)
{
	return container_of(clone, struct r0zone_tio, clone);
}

static void r0zone_update_zone_wp(struct r0zone_target *szt, struct bio *bio)
{
	unsigned int zone_id = sector_to_zone(szt, bio->bi_iter.bi_sector);
	struct r0zone_zone *zone = xa_load(&szt->metadata->zones, zone_id);

	zone->_wp += bio->bi_iter.bi_size >> SECTOR_SHIFT;
}

static void r0zone_submit_bio(struct r0zone_target *szt, struct bio *bio)
{
	BUG_ON(bio_sectors(bio) > szt->chunk_size_sectors);

	/*
	 * Remap the split bio with the physical address
	 */
	bio->bi_iter.bi_sector = l2p_sect(szt, bio->bi_iter.bi_sector);
	submit_bio_noacct(bio);

	if (bio_op(bio) == REQ_OP_WRITE)
		r0zone_update_zone_wp(szt, bio);
}

static void r0zone_split_bio(struct r0zone_target *szt, struct bio *bio,
		sector_t size)
{
	struct bio *split = bio_split(bio, size, GFP_NOIO,
			&szt->bio_set);
	bio_chain(split, bio);
	r0zone_submit_bio(szt, split);
}

static int r0zone_rw(struct r0zone_target *szt, struct bio *bio)
{
	sector_t start = bio->bi_iter.bi_sector;
	sector_t _start;

	bio_set_dev(bio, szt->dev->bdev);

	/*
	 * Round down the very first bio aligned to the chunk size.
	 */
	_start = round_down(start << SECTOR_SHIFT, chunk_size) >>
			SECTOR_SHIFT;
	if (start != _start && start - _start < bio_sectors(bio))
		r0zone_split_bio(szt, bio, start - _start);

	while (bio->bi_iter.bi_size > chunk_size)
		r0zone_split_bio(szt, bio, szt->chunk_size_sectors);


	r0zone_submit_bio(szt, bio);
	return DM_MAPIO_SUBMITTED;
}

static int r0zone_map(struct dm_target *ti, struct bio *bio)
{
        struct r0zone_target *szt = (struct r0zone_target *) ti->private;

	switch (bio_op(bio)) {
	case REQ_OP_READ:
	case REQ_OP_WRITE:
		return r0zone_rw(szt, bio);
	default:
		pr_err("invalid operation of bio\n");
		return -EINVAL;
	}
}

static int r0zone_init_or_update_zone(struct blk_zone *blkz, unsigned int num,
		void *data)
{
	struct r0zone_target *szt = data;
	struct r0zone_metadata *meta = szt->metadata;
	struct r0zone_zone *zone;

	if ((zone = xa_load(&meta->zones, num)))
		goto update;

	zone = kzalloc(sizeof(struct r0zone_zone), GFP_KERNEL);
	if (!zone)
		return -ENOMEM;

	if (xa_insert(&meta->zones, num, zone, GFP_KERNEL)) {
		pr_err("failed to insert zone to metadata");
		kfree(zone);
		return -ENOMEM;
	}

	zone->id = num;
	zone->slba = (blkz->start << SECTOR_SHIFT) >>
		ilog2(szt->logical_block_size);
	zone->szt = szt;
	zone->_start = blkz->start;
	szt->zone_capacity = blkz->capacity;
	szt->lzone_capacity = szt->zone_capacity * STRIPE_SIZE;

update:
	zone->wp = (blkz->wp<< SECTOR_SHIFT) >> ilog2(szt->logical_block_size);
	zone->_wp = blkz->wp;
	return 0;
}

/*
 * `num` is given as a logical zone number.
 */
static int r0zone_report_zones_cb(struct blk_zone *blkz, unsigned int num,
		void *data)
{
	struct dm_report_zones_args *args = data;
	struct r0zone_target *szt = args->tgt->private;
	struct r0zone_metadata *meta = szt->metadata;
	unsigned int logical_zone_id = num + (args->start / szt->zone_size);
	unsigned int physical_zone_id = logical_zone_id * STRIPE_SIZE;
	int i;

	if (logical_zone_id >= szt->nr_physical_zones / STRIPE_SIZE) {
		args->next_sector = get_capacity(szt->dev->bdev->bd_disk);
		return 0;
	}

	blkz->wp = 0;
	for (i = 0; i < STRIPE_SIZE; i++) {
		struct r0zone_zone *zone = xa_load(&meta->zones,
				physical_zone_id + i);
		if (!zone)
			return 0;
		blkz->wp += zone->_wp - zone->_start;
	}

	blkz->start = logical_zone_id * szt->lzone_size;
	blkz->wp += blkz->start;
	blkz->len = szt->lzone_size;
	blkz->capacity = szt->lzone_capacity;

	return args->orig_cb(blkz, args->zone_idx++, args->orig_data);
}

static int r0zone_report_zones(struct dm_target *ti,
		struct dm_report_zones_args *args, unsigned int nr_zones)
{
	struct r0zone_target *szt  = ti->private;

	args->start = args->next_sector / STRIPE_SIZE;

	return blkdev_report_zones(szt->dev->bdev,
			args->start, nr_zones, r0zone_report_zones_cb, args);
}

static int r0zone_init_metadata(struct r0zone_target *szt)
{
	struct r0zone_metadata *meta;
	int ret;

	meta = kzalloc(sizeof(struct r0zone_metadata), GFP_KERNEL);
	if (!meta)
		return -ENOMEM;

	szt->metadata = meta;

	INIT_LIST_HEAD(&meta->free_zones_list);
	INIT_LIST_HEAD(&meta->partial_zones_list);
	INIT_LIST_HEAD(&meta->full_zones_list);

	xa_init(&meta->zones);

	ret = blkdev_report_zones(szt->dev->bdev, 0, BLK_ALL_ZONES,
			r0zone_init_or_update_zone, szt);
	if (ret < 0) {
		pr_err("dm-strzone: Failed to report zones, error %d\n", ret);
		return ret;
	}

	pr_info("dm-strzone: %s: Initialized zones %u\n", szt->dev->name,
			szt->nr_zones);

	return 0;
}

static void r0zone_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct r0zone_target *szt = ti->private;

	/*
	 * XXX: if we update chunk_sectors here,
	 * validate_hardware_zoned_model() will fail due to difference between
	 * the physical zone size and the logical one.  So, we commented the
	 * error check part in that function.
	 */
	limits->chunk_sectors = szt->lzone_size;
	limits->max_sectors = szt->lzone_size;
}

static void r0zone_update_chunk_sectors(struct dm_target *ti)
{
	struct r0zone_target *szt = (struct r0zone_target *) ti->private;
	struct mapped_device *md = dm_table_get_md(ti->table);

	md->queue->limits.chunk_sectors = szt->lzone_size;
}

static int r0zone_ctr(struct dm_target *ti, unsigned int argc,
                char **argv)
{
        struct r0zone_target *szt;
	unsigned int front_pad;

        szt = kzalloc(sizeof(struct r0zone_target), GFP_KERNEL);
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
	szt->chunk_size_sectors = chunk_size >> SECTOR_SHIFT;
	szt->zone_size = bdev_zone_sectors(szt->dev->bdev);
	if (!szt->zone_size) {
		pr_err("%s: Invalid chunk_sectors 0\n", "strzone");
		goto out;
	}
	szt->lzone_size = szt->zone_size * STRIPE_SIZE;
	szt->zone_size_shift = ilog2(szt->zone_size);
	szt->nr_physical_zones = disk_nr_zones(szt->dev->bdev->bd_disk);

	/*
	 * zone capacity will be filled up in a report-zone stage.
	 */
	szt->zone_capacity = 0;
	szt->lzone_capacity = 0;
	front_pad = __alignof__(struct r0zone_tio) + DM_STRZONE_TIO_BIO_OFFSET;
	if (bioset_init(&szt->bio_set, 8192, front_pad, 0))
		goto out;

        ti->private = szt;

	r0zone_init_metadata(szt);
	r0zone_update_chunk_sectors(ti);

	pr_info("dm-strzone: %s: chunk_size=%u bytes, zone_size=%lld bytes, zone_capacity=%lld bytes\n", szt->dev->name, chunk_size,
			szt->zone_size << SECTOR_SHIFT,
			szt->zone_capacity << SECTOR_SHIFT);

        return 0;
out:
        kfree(szt);
        return -EINVAL;
}

static void r0zone_dtr(struct dm_target *ti)
{
        struct r0zone_target *szt = (struct r0zone_target *) ti->private;

        dm_put_device(ti, szt->dev);
        kfree(szt);
}

static int r0zone_iterate_devices(struct dm_target *ti,
				  iterate_devices_callout_fn fn, void *data)
{
	struct r0zone_target *szt = ti->private;

	return fn(ti, szt->dev, szt->start, ti->len, data);
}

static struct target_type strzone = {
        .name = "r0zone",
        .version = {1, 0, 0},
        .module = THIS_MODULE,
        .ctr = r0zone_ctr,
        .dtr = r0zone_dtr,
        .map = r0zone_map,
	.features = DM_TARGET_ZONED_HM,
	.report_zones = r0zone_report_zones,
	.iterate_devices = r0zone_iterate_devices,
	.io_hints = r0zone_io_hints,
};

int __init dm_r0zone_init(void)
{
        dm_register_target(&strzone);

        return 0;
}

void __exit dm_r0zone_exit(void)
{
        dm_unregister_target(&strzone);
}

module_init(dm_r0zone_init);
module_exit(dm_r0zone_exit);

MODULE_LICENSE("GPL");
