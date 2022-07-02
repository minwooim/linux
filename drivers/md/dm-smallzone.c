#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/bio.h>
#include <linux/device-mapper.h>

struct smallzone_target {
        struct dm_dev *dev;
        sector_t start;
};

static int smallzone_map(struct dm_target *ti, struct bio *bio)
{
        struct smallzone_target *szt = (struct smallzone_target *) ti->private;

        bio->bi_bdev = szt->dev->bdev;

        submit_bio(bio);

        return DM_MAPIO_SUBMITTED;
}

static sector_t smallzone_map_sector(struct dm_target *ti, sector_t bi_sector)
{
	struct smallzone_target *szt = ti->private;

	return szt->start + dm_target_offset(ti, bi_sector);
}

static int smallzone_report_zones(struct dm_target *ti,
		struct dm_report_zones_args *args, unsigned int nr_zones)
{
	struct smallzone_target *szt  = ti->private;

	return dm_report_zones(szt->dev->bdev, szt->start,
			       smallzone_map_sector(ti, args->next_sector),
			       args, nr_zones);
}

static int smallzone_ctr(struct dm_target *ti, unsigned int argc,
                char **argv)
{
        struct smallzone_target *szt;
        unsigned long long start;
        char dummy;

        if (argc != 2)
                return -EINVAL;

        szt = kmalloc(sizeof(struct smallzone_target), GFP_KERNEL);
        if (!szt)
                return -ENOMEM;

        if (sscanf(argv[1], "%llu%c", &start, &dummy) != 1 ||
                        start != (sector_t)start)
                goto out;

        szt->start = (sector_t) start;

        if (dm_get_device(ti, argv[0], dm_table_get_mode(ti->table),
                                &szt->dev)) {
                ti->error = "dm_smallzone: Device lookup failed";
                goto out;
        }

        ti->private = szt;

        return 0;
out:
        kfree(szt);
        return -EINVAL;
}

static void smallzone_dtr(struct dm_target *ti)
{
        struct smallzone_target *szt = (struct smallzone_target *) ti->private;

        dm_put_device(ti, szt->dev);
        kfree(szt);
}

static int smallzone_iterate_devices(struct dm_target *ti,
				  iterate_devices_callout_fn fn, void *data)
{
	struct smallzone_target *szt = ti->private;

	return fn(ti, szt->dev, szt->start, ti->len, data);
}

static struct target_type smallzone = {
        .name = "smallzone",
        .version = {1, 0, 0},
        .module = THIS_MODULE,
        .ctr = smallzone_ctr,
        .dtr = smallzone_dtr,
        .map = smallzone_map,
	.features = DM_TARGET_ZONED_HM,
	.report_zones = smallzone_report_zones,
	.iterate_devices = smallzone_iterate_devices,
};

int __init dm_smallzone_init(void)
{
        dm_register_target(&smallzone);

        return 0;
}

void dm_smallzone_exit(void)
{
        dm_unregister_target(&smallzone);
}
