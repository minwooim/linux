#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/bio.h>
#include <linux/device-mapper.h>

#include "dm-core.h"

#define KB	(1024)

/* XXX: it should be retrived from the controller by an admin command */
#define OPTIMAL_WRITE_SIZE	(128 * KB)

static unsigned int stripe_size = 4;
module_param(stripe_size, uint, 0644);

/*
 * Must be power-of-2 and larger than 4KB.
 */
static unsigned int chunk_size = 128 * KB;
module_param(chunk_size, uint, 0644);

struct r0zone_metadata {
	struct xarray zones;
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
	struct bio *parent;
	struct r0zone_target *szt;
	unsigned int nr_split_bios;
	atomic_t io_count;

	struct bio **clone;
};

struct r0zone_tio {
	struct r0zone_io *io;
	struct bio clone;
};
#define DM_STRZONE_TIO_BIO_OFFSET \
	(offsetof(struct r0zone_tio, clone))

struct r0zone_zone {
	sector_t _start;
	sector_t _wp;
};

static inline sector_t l2p_sect(struct r0zone_target *target, sector_t sector)
{
	int lstart = sector / target->lzone_size;
	sector_t loffset = sector - (lstart * target->lzone_size);
	sector_t pstart = lstart * stripe_size * target->zone_size;

	/*
	 * Example of chunk mapping for (stripe_size = 4)
	 *
	 * |---------------------|	logical zone
	 *
	 * |---| |---| |---| |---|	physical zones
	 *  0     1     2     3		row=0
	 *   4     5     6     7	row=1
	 *    8     9     ...		row=2
	 * col=0 col=1 col=2 col=3
	 */
	int chunk = loffset / target->chunk_size_sectors;
	sector_t remain = loffset % target->chunk_size_sectors;
	int row = chunk / stripe_size;
	int col = chunk & (stripe_size - 1);

	return pstart + (col * target->zone_size) +
		(row * target->chunk_size_sectors) + remain;
}

static inline unsigned int sector_to_zone(struct r0zone_target *target,
		sector_t sector)
{
	return sector / target->zone_size;
}

static void r0zone_update_zone_wp(struct r0zone_target *szt, struct bio *bio)
{
	unsigned int zone_id = sector_to_zone(szt, bio->bi_iter.bi_sector);
	struct r0zone_zone *zone = xa_load(&szt->metadata->zones, zone_id);

	zone->_wp += bio->bi_iter.bi_size >> SECTOR_SHIFT;
}

static void r0zone_reset_zone_wp(struct r0zone_target *szt, struct bio *bio)
{
	unsigned int zone_id = sector_to_zone(szt, bio->bi_iter.bi_sector);
	struct r0zone_zone *zone = xa_load(&szt->metadata->zones, zone_id);

	zone->_wp = zone->_start;
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

static void r0zone_bio_endio(struct r0zone_io *io)
{
	bio_endio(io->parent);
	kfree(io->clone);
	kfree(io);
}

static void r0zone_dec_pending(struct r0zone_io *io)
{
	if (atomic_dec_and_test(&io->io_count))
		r0zone_bio_endio(io);
}

static void r0zone_split_endio(struct bio *bio)
{
	struct r0zone_tio *tio = container_of(bio, struct r0zone_tio, clone);
	struct r0zone_io *io = tio->io;

	bio_put(bio);
	r0zone_dec_pending(io);
}

static void r0zone_clone_endio(struct bio *bio)
{
	bio_put(bio);
}

static void r0zone_split_bio(struct r0zone_target *szt, struct r0zone_io *io,
		sector_t size, unsigned int bio_idx)
{
	struct bio *split = bio_alloc_clone(NULL, io->parent, GFP_NOIO,
			&szt->bio_set);
	struct r0zone_tio *tio;

	if (!split)
		return;

	split->bi_end_io = r0zone_split_endio;
	split->bi_iter.bi_size = size << SECTOR_SHIFT;
	bio_set_dev(split, szt->dev->bdev);

	tio = container_of(split, struct r0zone_tio, clone);
	tio->io = io;
	io->clone[bio_idx] = split;
	atomic_inc(&io->io_count);

	if (bio_sectors(split) < bio_sectors(io->parent))
		bio_advance(io->parent, size << SECTOR_SHIFT);

	r0zone_submit_bio(szt, split);
}

static unsigned int r0zone_nr_split_bios(struct bio *bio)
{
	unsigned int nr_split_bios = 0;
	sector_t start = bio->bi_iter.bi_sector;
	sector_t _start;
	unsigned int bi_size = bio->bi_iter.bi_size;

	_start = round_up(start << SECTOR_SHIFT, chunk_size) >>
			SECTOR_SHIFT;
	if (start != _start && _start - start < (bi_size >> 9)) {
		nr_split_bios++;
		bi_size -= (_start - start) << 9;
	}

	while (bi_size > chunk_size) {
		nr_split_bios++;
		bi_size -= chunk_size;
	}

	if (bi_size)
		nr_split_bios++;
	return nr_split_bios;
}

static int r0zone_rw(struct r0zone_target *szt, struct bio *bio)
{
	sector_t start = bio->bi_iter.bi_sector;
	sector_t _start;
	struct r0zone_io *io;
	unsigned int bio_idx = 0;
	struct r0zone_tio *tio;

	if (r0zone_nr_split_bios(bio) < 2) {
		bio_set_dev(bio, szt->dev->bdev);
		r0zone_submit_bio(szt, bio);
		return DM_MAPIO_SUBMITTED;
	}

	io = kzalloc(sizeof(struct r0zone_io), GFP_KERNEL);
	if (!io)
		return -ENOMEM;

	bio_set_dev(bio, szt->dev->bdev);

	atomic_set(&io->io_count, 0);
	io->nr_split_bios = r0zone_nr_split_bios(bio);
	io->szt = szt;
	io->parent = bio;
	io->clone = kmalloc(sizeof(struct bio *) * io->nr_split_bios,
			GFP_KERNEL);
	if (!io->clone)
		return -ENOMEM;

	/*
	 * Round down the very first bio aligned to the chunk size.
	 */
	_start = round_up(start << SECTOR_SHIFT, chunk_size) >>
			SECTOR_SHIFT;
	if (start != _start && _start - start < bio_sectors(bio))
		r0zone_split_bio(szt, io, _start - start, bio_idx++);

	while (bio->bi_iter.bi_size > chunk_size)
		r0zone_split_bio(szt, io, szt->chunk_size_sectors, bio_idx++);

	if (bio_sectors(bio)) {
		struct bio *last_bio = bio_alloc_clone(NULL, bio, GFP_NOIO,
				&szt->bio_set);

		bio_set_dev(last_bio, szt->dev->bdev);
		last_bio->bi_end_io = r0zone_split_endio;
		tio = container_of(last_bio, struct r0zone_tio, clone);
		tio->io = io;
		io->clone[bio_idx++] = last_bio;
		atomic_inc(&io->io_count);

		r0zone_submit_bio(szt, last_bio);
	}

	return DM_MAPIO_SUBMITTED;
}

static int r0zone_zone_reset(struct r0zone_target *szt, struct bio *bio)
{
	sector_t start = bio->bi_iter.bi_sector;
	int i;

	for (i = 1; i < stripe_size; i++) {
		struct bio *clone = bio_alloc_clone(NULL, bio, GFP_NOIO,
				&szt->bio_set);

		clone->bi_end_io = r0zone_clone_endio;
		clone->bi_iter.bi_sector =
			l2p_sect(szt, start) + i * szt->zone_size;
		bio_set_dev(clone, szt->dev->bdev);

		r0zone_reset_zone_wp(szt, clone);
		submit_bio(clone);
	}

	bio_set_dev(bio, szt->dev->bdev);
	bio->bi_iter.bi_sector = l2p_sect(szt, start);
	r0zone_reset_zone_wp(szt, bio);
	submit_bio(bio);
	return DM_MAPIO_SUBMITTED;
}

static int r0zone_map(struct dm_target *ti, struct bio *bio)
{
        struct r0zone_target *szt = (struct r0zone_target *) ti->private;

	switch (bio_op(bio)) {
	case REQ_OP_READ:
	case REQ_OP_WRITE:
		return r0zone_rw(szt, bio);
	case REQ_OP_ZONE_RESET:
		return r0zone_zone_reset(szt, bio);
	default:
		pr_err("invalid operation of bio %d\n", bio_op(bio));
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

	zone->_start = blkz->start;
	szt->zone_capacity = blkz->capacity;
	szt->lzone_capacity = szt->zone_capacity * stripe_size;

update:
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
	unsigned int physical_zone_id = logical_zone_id * stripe_size;
	int i;

	if (logical_zone_id >= szt->nr_physical_zones / stripe_size) {
		args->next_sector = get_capacity(szt->dev->bdev->bd_disk);
		return 0;
	}

	blkz->wp = 0;
	for (i = 0; i < stripe_size; i++) {
		struct r0zone_zone *zone = xa_load(&meta->zones,
				physical_zone_id + i);
		if (!zone)
			return 0;
		blkz->wp += zone->_wp - zone->_start;
	}

	blkz->start = logical_zone_id * szt->lzone_size;
	if (!blkz->wp)
		blkz->cond = BLK_ZONE_COND_EMPTY;
	else if (blkz->wp < szt->lzone_capacity)
		blkz->cond = BLK_ZONE_COND_IMP_OPEN;
	else
		blkz->cond = BLK_ZONE_COND_FULL;

	blkz->wp += blkz->start;
	blkz->len = szt->lzone_size;
	blkz->capacity = szt->lzone_capacity;

	args->next_sector = blkz->start + blkz->len;

	return args->orig_cb(blkz, args->zone_idx++, args->orig_data);
}

static int r0zone_report_zones(struct dm_target *ti,
		struct dm_report_zones_args *args, unsigned int nr_zones)
{
	struct r0zone_target *szt  = ti->private;

	args->start = args->next_sector / stripe_size;

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
	szt->lzone_size = szt->zone_size * stripe_size;
	szt->zone_size_shift = ilog2(szt->zone_size);
	szt->nr_physical_zones = disk_nr_zones(szt->dev->bdev->bd_disk);

	/*
	 * zone capacity will be filled up in a report-zone stage.
	 */
	szt->zone_capacity = 0;
	szt->lzone_capacity = 0;
	front_pad = __alignof__(struct r0zone_tio) + DM_STRZONE_TIO_BIO_OFFSET;
	if (bioset_init(&szt->bio_set, 256, front_pad, 0))
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
	unsigned long idx;
	struct r0zone_zone *zone;

        dm_put_device(ti, szt->dev);

	bioset_exit(&szt->bio_set);
	xa_for_each(&szt->metadata->zones, idx, zone) {
		kfree(zone);
	}
	xa_destroy(&szt->metadata->zones);
	kfree(szt->metadata);
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
