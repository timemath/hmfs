#include <linux/fs.h>
#include <linux/module.h>
//#include <linux/backing-dev.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/freezer.h>
//#include <linux/blkdev.h>

#include "hmfs.h"
#include "node.h"
//#include "segment.h"
#include "gc.h"

//static struct kmem_cache *winode_slab;

int hmfs_gc(struct hmfs_sb_info *sbi)
{
        /**
        struct list_head ilist;
        unsigned int segno, i;
        int gc_type = BG_GC;
        int nfree = 0;
        int ret = -1;

        INIT_LIST_HEAD(&ilist);
gc_more:
        if (!(sbi->sb->s_flags & MS_ACTIVE))
                goto stop;

        if (gc_type == BG_GC && has_not_enough_free_secs(sbi, nfree)) {
                gc_type = FG_GC;
                write_checkpoint(sbi, false);
        }

        if (!__get_victim(sbi, &segno, gc_type, NO_CHECK_TYPE))
                goto stop;
        ret = 0;

        for (i = 0; i < sbi->segs_per_sec; i++)
                do_garbage_collect(sbi, segno + i, &ilist, gc_type);

        if (gc_type == FG_GC) {
                sbi->cur_victim_sec = NULL_SEGNO;
                nfree++;
                WARN_ON(get_valid_blocks(sbi, segno, sbi->segs_per_sec));
        }

        if (has_not_enough_free_secs(sbi, nfree))
                goto gc_more;

        if (gc_type == FG_GC)
                write_checkpoint(sbi, false);
stop:
        mutex_unlock(&sbi->gc_mutex);

        put_gc_inode(&ilist);
        return ret;*/
        return 0;
}



static int gc_thread_func(void *data)
{
	struct hmfs_sb_info *sbi = data;
	wait_queue_head_t *wq = &sbi->gc_thread->gc_wait_queue_head;
	long wait_ms;

	wait_ms = GC_THREAD_MIN_SLEEP_TIME;

	do {
		if (try_to_freeze())
			continue;
		else
			wait_event_interruptible_timeout(*wq,
						kthread_should_stop(),
						msecs_to_jiffies(wait_ms));
		if (kthread_should_stop())
			break;

		if (sbi->sb->s_writers.frozen >= SB_FREEZE_WRITE) {
			wait_ms = GC_THREAD_MAX_SLEEP_TIME;
			continue;
		}

		/*
		 * [GC triggering condition]
		 * 0. GC is not conducted currently.
		 * 1. There are enough dirty segments.
		 * 2. IO subsystem is idle by checking the # of writeback pages.
		 * 3. IO subsystem is idle by checking the # of requests in
		 *    bdev's request list.
		 *
		 * Note) We have to avoid triggering GCs too much frequently.
		 * Because it is possible that some segments can be
		 * invalidated soon after by user update or deletion.
		 * So, I'd like to wait some time to collect dirty segments.
		 */
		if (!mutex_trylock(&sbi->gc_mutex))
			continue;

		if (!is_idle(sbi)) {
			wait_ms = increase_sleep_time(wait_ms);
			mutex_unlock(&sbi->gc_mutex);
			continue;
		}

		if (has_enough_invalid_pages(sbi))
			wait_ms = decrease_sleep_time(wait_ms);
		else
			wait_ms = increase_sleep_time(wait_ms);
#ifdef CONFIG_HMFS_STAT_FS
		sbi->bg_gc++;
#endif

		/* if return value is not zero, no victim was selected */
		//TODO need to complete the hmfs_gc function 
		if (hmfs_gc(sbi))
			wait_ms = GC_THREAD_NOGC_SLEEP_TIME;
	} while (!kthread_should_stop());
	return 0;
}

int start_gc_thread(struct hmfs_sb_info *sbi)
{
	struct hmfs_gc_kthread *gc_th;
	//get device info 
	//dev_t dev = sbi->sb->s_bdev->bd_dev;
	int err = 0;

	//if (!test_opt(sbi, BG_GC))
	//	goto out;
	gc_th = kmalloc(sizeof(struct hmfs_gc_kthread), GFP_KERNEL);
	if (!gc_th) {
		err = -ENOMEM;
		goto out;
	}

	sbi->gc_thread = gc_th;
	init_waitqueue_head(&sbi->gc_thread->gc_wait_queue_head);
	sbi->gc_thread->hmfs_gc_task = kthread_run(gc_thread_func, sbi,"hmfs_gc-%u:%u",1,1);// MAJOR(dev), MINOR(dev));
	if (IS_ERR(gc_th->hmfs_gc_task)) {
		err = PTR_ERR(gc_th->hmfs_gc_task);
		kfree(gc_th);
		sbi->gc_thread = NULL;
	}

out:
	return err;
}

void stop_gc_thread(struct hmfs_sb_info *sbi)
{
	struct hmfs_gc_kthread *gc_th = sbi->gc_thread;
	if (!gc_th)
		return;
	kthread_stop(gc_th->hmfs_gc_task);
	kfree(gc_th);
	sbi->gc_thread = NULL;
}

static int select_gc_type(int gc_type)
{
	return (gc_type == BG_GC) ? GC_CB : GC_GREEDY;
}


static void select_policy(struct hmfs_sb_info *sbi, int gc_type,
			int type, struct victim_sel_policy *p)
{
	//TODO here need to be completed in segment.h
	//struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);

	if (p->alloc_mode == SSR) {
		p->gc_mode = GC_GREEDY;
		//p->dirty_segmap = dirty_i->dirty_segmap[type];
		p->ofs_unit = 1;
	} else {
		p->gc_mode = select_gc_type(gc_type);
		//p->dirty_segmap = dirty_i->dirty_segmap[DIRTY];
		p->ofs_unit = sbi->segs_per_sec;
	}
	p->offset = sbi->last_victim[p->gc_mode];
}


static unsigned int get_max_cost(struct hmfs_sb_info *sbi,
				struct victim_sel_policy *p)
{
	/* SSR allocates in a segment unit */
	if (p->alloc_mode == SSR)
		return 1 << sbi->log_pages_per_seg;
	if (p->gc_mode == GC_GREEDY)
		return (1 << sbi->log_pages_per_seg) * p->ofs_unit;
	else if (p->gc_mode == GC_CB)
		return UINT_MAX;
	else /* No other gc_mode */
		return 0;
}

static unsigned int check_bg_victims(struct hmfs_sb_info *sbi)
{
	//struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	unsigned int hint = 0;
	unsigned int secno;

	/*
	 * If the gc_type is FG_GC, we can select victim segments
	 * selected by background GC before.
	 * Those segments guarantee they have small valid blocks.
	 */
next:
	//TODO need to be completed in segment.c
	/**secno = find_next_bit(dirty_i->victim_secmap, TOTAL_SECS(sbi), hint++);
	if (secno < TOTAL_SECS(sbi)) {
		if (sec_usage_check(sbi, secno))
			goto next;
		clear_bit(secno, dirty_i->victim_secmap);
		return secno * sbi->segs_per_sec;
	}*/
	return NULL_SEGNO;
}


static unsigned int get_cb_cost(struct hmfs_sb_info *sbi, unsigned int segno)
{
	struct sit_info *sit_i = SIT_I(sbi);
	unsigned int secno = GET_SECNO(sbi, segno);
	unsigned int start = secno * sbi->segs_per_sec;
	unsigned long long mtime = 0;
	unsigned int vblocks;
	unsigned char age = 0;
	unsigned char u;
	unsigned int i;

	for (i = 0; i < sbi->segs_per_sec; i++)
		mtime += get_seg_entry(sbi, start + i)->mtime;
	vblocks = get_valid_blocks(sbi, segno, sbi->segs_per_sec);

	mtime = div_u64(mtime, sbi->segs_per_sec);
	vblocks = div_u64(vblocks, sbi->segs_per_sec);

	u = (vblocks * 100) >> sbi->log_blocks_per_seg;

	/* Handle if the system time is changed by user */
	if (mtime < sit_i->min_mtime)
		sit_i->min_mtime = mtime;
	if (mtime > sit_i->max_mtime)
		sit_i->max_mtime = mtime;
	if (sit_i->max_mtime != sit_i->min_mtime)
		age = 100 - div64_u64(100 * (mtime - sit_i->min_mtime),
				sit_i->max_mtime - sit_i->min_mtime);

	return UINT_MAX - ((100 * (100 - u) * age) / (100 + u));
}
