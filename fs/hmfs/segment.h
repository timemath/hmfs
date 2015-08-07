#ifndef _LINUX_SEGMENT_H
#define _LINUX_SEGMENT_H

#include "hmfs.h"
typedef u64 block_t;		//bits per NVM page address 

#define hmfs_bitmap_size(nr)			\
	(BITS_TO_LONGS(nr) * sizeof(unsigned long))
#define TOTAL_SEGS(sbi)	(SM_I(sbi)->main_segments)

/* constant macro */
#define NULL_SEGNO			((unsigned int)(~0))
#define SIT_ENTRY_OFFSET(sit_i, segno)					\
	(segno % sit_i->sents_per_block)
#define SIT_BLOCK_OFFSET(sit_i, segno)					\
	(segno / SIT_ENTRY_PER_BLOCK)
#define GET_SECNO(sbi, segno)					\
	((segno) / sbi->segs_per_sec)


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


struct seg_entry {
	unsigned short valid_blocks;	/* # of valid blocks */
	unsigned char *cur_valid_map;	/* validity bitmap of blocks */

	unsigned short ckpt_valid_blocks;

	unsigned char type;		/* segment type like CURSEG_XXX_TYPE */
	unsigned long long mtime;	/* modification time of the segment */
};

struct sec_entry {
	unsigned int valid_blocks;	/* # of valid blocks in a section */
};

struct sit_info {
	const struct segment_allocation *s_ops;

	block_t sit_root;	/* root node address of SIT file */
	block_t sit_blocks;	/* # of blocks used by SIT file */
	block_t written_valid_blocks;	/* # of valid blocks in main area */
	char *sit_bitmap;	/* SIT bitmap pointer */
	unsigned int bitmap_size;	/* SIT bitmap size */

	unsigned long *dirty_sentries_bitmap;	/* bitmap for dirty sentries */
	unsigned int dirty_sentries;		/* # of dirty sentries */
	unsigned int sents_per_block;	/* # of SIT entries per block */
	struct mutex sentry_lock;	/* to protect SIT cache */
	struct seg_entry *sentries;	/* SIT segment-level cache */
	struct sec_entry *sec_entries;		/* SIT section-level cache */

	/* for cost-benefit algorithm in cleaning procedure */
	unsigned long long elapsed_time;	/* elapsed time after mount */
	unsigned long long mounted_time;	/* mount time */
	unsigned long long min_mtime;		/* min. modification time */
	unsigned long long max_mtime;		/* max. modification time */
};

struct free_segmap_info {
	unsigned int start_segno;	/* start segment number logically */
	unsigned int free_segments;	/* # of free segments */
	rwlock_t segmap_lock;	/* free segmap lock */
	unsigned long *free_segmap;	/* free segment bitmap */
};
/* for active log information */
struct curseg_info {
	struct mutex curseg_mutex;	/* lock for consistency */
	struct hmfs_summary_block *sum_blk;     /* cached summary block */
	//unsigned char alloc_type;               /* current allocation type */
	unsigned int segno;	/* current segment number */
	unsigned short next_blkoff;	/* next block offset to write */
	unsigned int next_segno;	/* preallocated segment */
};

struct hmfs_sm_info {
	struct sit_info *sit_info;	/* whole segment information */
	struct free_segmap_info *free_info;	/* free segment information */
	struct dirty_seglist_info *dirty_info;	/* dirty segment information */

	struct curseg_info *curseg_array;	/* active segment information */

	struct list_head wblist_head;	/* list of under-writeback pages */
	spinlock_t wblist_lock;	/* lock for checkpoint */

	block_t seg0_blkaddr;	/* TODO:block address of 0'th segment */
	block_t main_blkaddr;	/* start block address of main area */
	block_t ssa_blkaddr;	/* start block address of SSA area */

	unsigned int segment_count;	/* total # of segments */
	unsigned int main_segments;	/* # of segments in main area */
	unsigned int reserved_segments;	/* # of reserved segments */
	unsigned int ovp_segments;	/* # of overprovision segments */
};

//static inline struct hmfs_sm_info *SM_I(struct hmfs_sb_info *sbi)
//{
//	return (struct hmfs_sm_info *)(sbi->sm_info);
//}

static inline struct dirty_seglist_info *DIRTY_I(struct hmfs_sb_info *sbi)
{
        return (struct dirty_seglist_info *)(SM_I(sbi)->dirty_info);
}

static inline struct sit_info *SIT_I(struct hmfs_sb_info *sbi)
{
        return (struct sit_info *)(SM_I(sbi)->sit_info);
}

static inline unsigned int prefree_segments(struct hmfs_sb_info *sbi)
{
        return DIRTY_I(sbi)->nr_dirty[PRE];
}


static inline struct seg_entry *get_seg_entry(struct hmfs_sb_info *sbi,
						unsigned int segno)
{
	//TODO need to be completed in segment.c
	//struct sit_info *sit_i = SIT_I(sbi);
	//return &sit_i->sentries[segno];
	return NULL;
}


static inline struct curseg_info *CURSEG_I(struct hmfs_sb_info *sbi)
{
	//TODO need to be completed in segment.c
	//return SM_I(sbi)->curseg_array;
	return NULL;
}

static inline struct free_segmap_info *FREE_I(struct hmfs_sb_info *sbi)
{
	//TODO need to be completed in segment.c
	//return SM_I(sbi)->free_info;
	return NULL;
}

static inline void __set_free(struct hmfs_sb_info *sbi, unsigned int segno)
{
	struct free_segmap_info *free_i = FREE_I(sbi);
	unsigned int start_segno = segno;
	unsigned int next;
	/* lock -- free&cnt -- unlock */
	write_lock(&free_i->segmap_lock);
	clear_bit(segno, free_i->free_segmap);
	free_i->free_segments++;
	write_unlock(&free_i->segmap_lock);
}

static inline void __set_inuse(struct hmfs_sb_info *sbi, unsigned int segno)
{
	struct free_segmap_info *free_i = FREE_I(sbi);
	//FIXME: do we need lock here?
	set_bit(segno, free_i->free_segmap);
	free_i->free_segments--;
}

static inline struct sec_entry *get_sec_entry(struct hmfs_sb_info *sbi,
						unsigned int segno)
{
	struct sit_info *sit_i = SIT_I(sbi);
	return &sit_i->sec_entries[GET_SECNO(sbi, segno)];
}

static inline unsigned int get_valid_blocks(struct hmfs_sb_info *sbi,
				unsigned int segno, int section)
{
	/*
	 * In order to get # of valid blocks in a section instantly from many
	 * segments, igned short valid_blocks;* # of valid blocks hmfs manages two counting structures separately.
	 */
	if (section > 1)
		return get_sec_entry(sbi, segno)->valid_blocks;
	else
		return get_seg_entry(sbi, segno)->valid_blocks;
}

#endif
