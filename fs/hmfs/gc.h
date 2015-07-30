#define GC_THREAD_MIN_WB_PAGES		1	/*
						 * a threshold to determine
						 * whether IO subsystem is idle
						 * or not
						 */
#define GC_THREAD_MIN_SLEEP_TIME	30000	/* milliseconds */
#define GC_THREAD_MAX_SLEEP_TIME	60000
#define GC_THREAD_NOGC_SLEEP_TIME	300000	/* wait 5 min */
#define LIMIT_INVALID_BLOCK	40 /* percentage over total user space */
#define LIMIT_FREE_BLOCK	40 /* percentage over invalid + free space */

/* Search max. number of dirty segments to select a victim segment */
#define MAX_VICTIM_SEARCH	20


//TODO start here need move to segment.h 

/* constant macro */
#define NULL_SEGNO			((unsigned int)(~0))
#define NULL_SECNO			((unsigned int)(~0))
/*
 * indicate a block allocation direction: RIGHT and LEFT.
 * RIGHT means allocating new sections towards the end of volume.
 * LEFT means the opposite direction.
 */
enum {
	ALLOC_RIGHT = 0,
	ALLOC_LEFT
};

/*
 * In the victim_sel_policy->alloc_mode, there are two block allocation modes.
 * LFS writes data sequentially with cleaning operations.
 * SSR (Slack Space Recycle) reuses obsolete space without cleaning operations.
 */
enum {
	LFS = 0,
	SSR
};

/*
 * In the victim_sel_policy->gc_mode, there are two gc, aka cleaning, modes.
 * GC_CB is based on cost-benefit algorithm.
 * GC_GREEDY is based on greedy algorithm.
 */
enum {
	GC_CB = 0,
	GC_GREEDY
};

/*
 * BG_GC means the background cleaning job.
 * FG_GC means the on-demand cleaning job.
 */
enum {
	BG_GC = 0,
	FG_GC
};

/* Notice: The order of dirty type is same with CURSEG_XXX in hmfs.h */
enum dirty_type {
	DIRTY_HOT_DATA,		/* dirty segments assigned as hot data logs */
	DIRTY_WARM_DATA,	/* dirty segments assigned as warm data logs */
	DIRTY_COLD_DATA,	/* dirty segments assigned as cold data logs */
	DIRTY_HOT_NODE,		/* dirty segments assigned as hot node logs */
	DIRTY_WARM_NODE,	/* dirty segments assigned as warm node logs */
	DIRTY_COLD_NODE,	/* dirty segments assigned as cold node logs */
	DIRTY,			/* to count # of dirty segments */
	PRE,			/* to count # of entirely obsolete segments */
	NR_DIRTY_TYPE
};

/**
#define IS_CURSEC(sbi, secno)						\
	((secno == CURSEG_I(sbi, CURSEG_HOT_DATA)->segno /		\
	  sbi->segs_per_sec) ||	\
	 (secno == CURSEG_I(sbi, CURSEG_WARM_DATA)->segno /		\
	  sbi->segs_per_sec) ||	\
	 (secno == CURSEG_I(sbi, CURSEG_COLD_DATA)->segno /		\
	  sbi->segs_per_sec) ||	\
	 (secno == CURSEG_I(sbi, CURSEG_HOT_NODE)->segno /		\
	  sbi->segs_per_sec) ||	\
	 (secno == CURSEG_I(sbi, CURSEG_WARM_NODE)->segno /		\
	  sbi->segs_per_sec) ||	\
	 (secno == CURSEG_I(sbi, CURSEG_COLD_NODE)->segno /		\
	  sbi->segs_per_sec))	\
*/

/* for a function parameter to select a victim segment */
struct victim_sel_policy {
	int alloc_mode;			/* LFS or SSR */
	int gc_mode;			/* GC_CB or GC_GREEDY */
	unsigned long *dirty_segmap;	/* dirty segment bitmap */
	unsigned int offset;		/* last scanned bitmap offset */
	unsigned int ofs_unit;		/* bitmap search unit */
	unsigned int min_cost;		/* minimum cost */
	unsigned int min_segno;		/* segment # having min. cost */
};

struct dirty_seglist_info {
	const struct victim_selection *v_ops;	/* victim selction operation */
	unsigned long *dirty_segmap[NR_DIRTY_TYPE];
	struct mutex seglist_lock;		/* lock for segment bitmaps */
	int nr_dirty[NR_DIRTY_TYPE];		/* # of dirty segments */
	unsigned long *victim_secmap;		/* background GC victims */
};

static inline bool sec_usage_check(struct hmfs_sb_info *sbi, unsigned int secno)
{
	//TODO need to be completed in segment.c
	//if (IS_CURSEC(sbi, secno) || (sbi->cur_victim_sec == secno))
	//	return true;
	return false;
}
// End here need move to segment.h

struct hmfs_gc_kthread {
	struct task_struct *hmfs_gc_task;
	wait_queue_head_t gc_wait_queue_head;
};

struct inode_entry {
	struct list_head list;
	struct inode *inode;
};

static inline int is_idle(struct hmfs_sb_info *sbi)
{
	//struct pages_device *bdev = sbi->sb->s_bdev;
	//struct request_queue *q = bdev_get_queue(bdev);
	//struct request_list *rl = &q->root_rl;
	//return !(rl->count[BLK_RW_SYNC]) && !(rl->count[BLK_RW_ASYNC]);
	return 1;
}


/*
 * inline functions
 */
static inline unsigned long free_user_pages(struct hmfs_sb_info *sbi)
{
	//TODO need to complete in segment.h
	//if (free_segments(sbi) < overprovision_segments(sbi))
		return 0;
	//else
	//	return (free_segments(sbi) - overprovision_segments(sbi))
	//		<< sbi->log_pages_per_seg;
}

static inline unsigned long limit_invalid_user_pages(struct hmfs_sb_info *sbi)
{
	return (long)(sbi->user_pages_count * LIMIT_INVALID_BLOCK) / 100;
}

static inline unsigned long limit_free_user_pages(struct hmfs_sb_info *sbi)
{

	unsigned long reclaimable_user_pages = sbi->user_pages_count;
 		//TODO need to be completed in segment.h
		//-written_pages_count(sbi);
	return (long)(reclaimable_user_pages * LIMIT_FREE_BLOCK) / 100;
}


static inline long increase_sleep_time(long wait)
{
	if (wait == GC_THREAD_NOGC_SLEEP_TIME)
		return wait;

	wait += GC_THREAD_MIN_SLEEP_TIME;
	if (wait > GC_THREAD_MAX_SLEEP_TIME)
		wait = GC_THREAD_MAX_SLEEP_TIME;
	return wait;
}

static inline long decrease_sleep_time(long wait)
{
	if (wait == GC_THREAD_NOGC_SLEEP_TIME)
		wait = GC_THREAD_MAX_SLEEP_TIME;

	wait -= GC_THREAD_MIN_SLEEP_TIME;
	if (wait <= GC_THREAD_MIN_SLEEP_TIME)
		wait = GC_THREAD_MIN_SLEEP_TIME;
	return wait;
}

static inline bool has_enough_invalid_pages(struct hmfs_sb_info *sbi)
{
	unsigned long invalid_user_pages = sbi->user_pages_count;
				//TODO need to complete in segment.h	
				// -written_pages_count(sbi);
	/*
	 * Background GC is triggered with the following condition.
	 * 1. There are a number of invalid pages.
	 * 2. There is not enough free space.
	 */
	if (invalid_user_pages > limit_invalid_user_pages(sbi) &&
			free_user_pages(sbi) < limit_free_user_pages(sbi))
		return true;
	return false;
}
