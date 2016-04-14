#include <linux/vmalloc.h>
#include "segment.h"

/*
 * Judge whether an address is a valid address. i.e.
 * it fall into space where we have actually writen data
 * into. It's different from valid bits in summary entry
 */

/*
 *  *cc1 is_valid_address:先根据参数获取当前指针指向的对象所在的段号
- * @sbi:指向超级块信息的指针实例
- * @addr:块地址
- * 如果该段号等于检查点指针的数据块所在的段号，则返回当前检查点所在的数据的偏移，证明该地址有效
- * 同理，如果等于当前node所在的段号，则返回当前检查点所在的node的偏移，也证明该地址有效
- * 否则，为无效地址,置为0
 */
bool is_valid_address(struct hmfs_sb_info *sbi, block_t addr)
{
	seg_t segno = GET_SEGNO(sbi, addr);
	struct hmfs_checkpoint *hmfs_cp = CM_I(sbi)->last_cp_i->cp;
	
	if (segno == le32_to_cpu(hmfs_cp->cur_data_segno))
		return GET_SEG_OFS(sbi, addr) <= le16_to_cpu(hmfs_cp->cur_data_blkoff);
	else if (segno == le32_to_cpu(hmfs_cp->cur_node_segno))
		return GET_SEG_OFS(sbi, addr) <= le16_to_cpu(hmfs_cp->cur_node_blkoff);
	else
		return get_seg_entry(sbi, segno)->valid_blocks > 0;
}
/*
  *cc2 total_valid_blocks：遍历main area区域所有段，计算某个超级块中用到的有效块的个数
- *@ sbi:指向超级块信息的指针实例
- *@ return:总的有效快的个数
 */

unsigned long total_valid_blocks(struct hmfs_sb_info *sbi)
{
	int i;
	unsigned long sum = 0;

	for (i = 0; i < TOTAL_SEGS(sbi); i++) {
		sum += get_valid_blocks(sbi, i);
	}

	return sum;
}
/*
  *cc3 get_seg_vblocks_in_summary:遍历SSA区域的当前段下，遍历每段每页每块的有效节点的个数
- *@ sbi:指向超级块信息的指针实例
- *@ segno:段号的类型
- *@ return:返回当前有效节点的个数
 */
unsigned long get_seg_vblocks_in_summary(struct hmfs_sb_info *sbi, seg_t segno)
{
	struct hmfs_summary_block *sum_blk;
	struct hmfs_summary *sum;
	int off = 0;
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	bool is_current;
	int count = 0;
	nid_t nid;
	
	sum_blk = get_summary_block(sbi, segno);
	sum = sum_blk->entries;

	//TODO: Set same part in garbage_collect as function
	for (off = 0; off < HMFS_PAGE_PER_SEG; ++off, sum++) {
		is_current = get_summary_start_version(sum) == cm_i->new_version;

		if (!get_summary_valid_bit(sum) && !is_current)
			continue;

		if (is_current) {
			nid = get_summary_nid(sum);
			if (IS_ERR(get_node(sbi, nid)))
				continue;
		}

		count++;
	}
	return count;
}

/*
  *cc4 __mark_sit_entry_dirty:记录当前段中SIT中脏的entry的个数
- *@sit_i：指向 SIT表的实例
- *@segno：段号的类型
- *@return:返回当前当前SIT总脏的entry的个数
 */
static void __mark_sit_entry_dirty(struct sit_info *sit_i, seg_t segno)
{
	if (!__test_and_set_bit(segno, sit_i->dirty_sentries_bitmap))
		sit_i->dirty_sentries++;
}

/* Return amount of blocks which has been invalidated */

/*
  *cc5 invalidate_delete_block:先判断当前块是否是最新版本的块，如果不是，根据块地址获取段号，同时将该段标记为脏
- *@sbi:指向超级块信息的指针实例
- *@addr:当前块的地址
- *@return:返回无效的块的数量
 */
int invalidate_delete_block(struct hmfs_sb_info *sbi, block_t addr)
{
	struct sit_info *sit_i = SIT_I(sbi);
	struct hmfs_summary *summary;
	seg_t segno;

	if (!is_new_block(sbi, addr))
		return 0;
	
	summary = get_summary_by_addr(sbi, addr);
	set_summary_nid(summary, NULL_NID);
	segno = GET_SEGNO(sbi, addr);
	lock_sentry(sit_i);
	update_sit_entry(sbi, segno, -1);
	unlock_sentry(sit_i);

	test_and_set_bit(segno, DIRTY_I(sbi)->dirty_segmap);
	return 1;
}

/*
 - *cc6 init_min_max_mtime:先锁定当前entry的表，然后遍历当前超级块中所有的段，同时设置所有段SIT的最大、最小mtime
- *@sbi:指向超级块信息的指针实例
 */
static void init_min_max_mtime(struct hmfs_sb_info *sbi)
{
	struct sit_info *sit_i = SIT_I(sbi);
	seg_t segno;
	unsigned long long mtime;


	lock_sentry(sit_i);
	sit_i->min_mtime = LLONG_MAX;

	for (segno = 0; segno < TOTAL_SEGS(sbi); segno++) {
		mtime = get_seg_entry(sbi, segno)->mtime;

		if (sit_i->min_mtime > mtime)
			sit_i->min_mtime = mtime;
	}
	sit_i->max_mtime = get_mtime(sbi);
	unlock_sentry(sit_i);
}
/*
 - *cc7 update_sit_entry:记录当前段的有效的块数，同时记录当前段的空闲的和脏的大小，并且根据新的有效块SITentry，更新当前段的entry信息
- *@sbi:指向超级块信息的指针实例
- *@segno：段号的类型
- *@del：段偏移
 */

void update_sit_entry(struct hmfs_sb_info *sbi, seg_t segno,
				int del)
{
	struct seg_entry *se;
	struct sit_info *sit_i = SIT_I(sbi);
	long new_vblocks;

	se = get_seg_entry(sbi, segno);
	new_vblocks = se->valid_blocks + del;

	hmfs_dbg_on(new_vblocks < 0 || new_vblocks > HMFS_PAGE_PER_SEG,
			"Invalid value of valid_blocks: %ld free:%d prefree:%d dirty:%d\n",
			new_vblocks, test_bit(segno, FREE_I(sbi)->free_segmap),
			test_bit(segno, FREE_I(sbi)->prefree_segmap), 
			test_bit(segno, DIRTY_I(sbi)->dirty_segmap));
	hmfs_bug_on(sbi, new_vblocks < 0 || new_vblocks > HMFS_PAGE_PER_SEG);

	se->valid_blocks = new_vblocks;
	se->mtime = get_mtime(sbi);
	__mark_sit_entry_dirty(sit_i, segno);
}

/*
 - *cc8 reset_curseg:重置当前段的未分配块的起始位置
- *@seg_i:当前段的段号
 */
static void reset_curseg(struct curseg_info *seg_i)
{
	atomic_set(&seg_i->segno, seg_i->next_segno);
	seg_i->next_blkoff = 0;
	seg_i->next_segno = NULL_SEGNO;
}

/*
 - *cc9  __cal_page_addr:根据段号和块偏移，返回当前mainarea的起始位置
- *@sbi:指向超级块信息的指针实例
- *@segno：当前段的段号
- *@blkoff:块偏移
- *@return:返回当前mainarea的起始位置
 */
inline block_t __cal_page_addr(struct hmfs_sb_info *sbi, seg_t segno,
				int blkoff)
{
	return (segno << HMFS_SEGMENT_SIZE_BITS) +
					(blkoff << HMFS_PAGE_SIZE_BITS)
					+ sbi->main_addr_start;
}
/*
 - *cc10 cal_page_addr:根据当前段号和要写的下一块偏移计算当前页的起始地址
- *@sbi:指向超级块信息的指针实例
- *@seg_i:当前段的段号
- *@return:计算当前页的起始地址ַ
 */
static inline unsigned long cal_page_addr(struct hmfs_sb_info *sbi,
				struct curseg_info *seg_i)
{
	return __cal_page_addr(sbi, atomic_read(&seg_i->segno),
				seg_i->next_blkoff);
}

/*
 * get_new_segment -- Find a new segment from the free segments bitmap
 * @newseg returns the found segment
 * must be success (otherwise cause error)
 */
/*
- *cc11 get_new_segment:遍历当前超级块下所有段，从空闲段的bitmap中，获取当前新的空闲的段的位置
- *@sbi:指向超级块信息的指针实例
- *@newseg:段号的类型
- *@return:每段空闲的位置
 */
int get_new_segment(struct hmfs_sb_info *sbi, seg_t *newseg)
{
	/*
     * free_i:获取完全空闲的块的实例（没有有效的块）
	 */
	struct free_segmap_info *free_i = FREE_I(sbi);
	seg_t segno;
	bool retry = false;
	int ret = 0;
	void *ssa;

	lock_write_segmap(free_i);
retry:
	segno = find_next_zero_bit(free_i->free_segmap,
				   TOTAL_SEGS(sbi), *newseg);
	if(segno >= TOTAL_SEGS(sbi)) {
		*newseg = 0;
		if(!retry) {
			retry = true;
			goto retry;
		}
		ret = -ENOSPC;
		goto unlock;
	}

	hmfs_bug_on(sbi, test_bit(segno, free_i->free_segmap));
	__set_inuse(sbi, segno);
	*newseg = segno;
	/* TODO: Need not to clear SSA */
	ssa = get_summary_block(sbi, segno);
	memset_nt(ssa, 0, HMFS_SUMMARY_BLOCK_SIZE);
unlock:
/*
 - * unlock_write_segmap：锁定要写的段
 */
	unlock_write_segmap(free_i);
	return ret;
}
/*
 - *cc12 move_to_new_segment:返回新的段的起始位置
- *@sbi:指向超级块信息的指针实例
- *@seg_i:获取当前active的段日志信息实例
- *@return:返回当前新的空闲段的起始位置
 */
static int move_to_new_segment(struct hmfs_sb_info *sbi,
				struct curseg_info *seg_i)
{
	/*
	 * ��ȡ��ǰ�Ķκ�
	 */
	seg_t segno = atomic_read(&seg_i->segno);
	int ret = get_new_segment(sbi, &segno);

	if (ret)
		return ret;
	/*
     * 获取当前的段号
	 */
	seg_i->next_segno = segno;
	reset_curseg(seg_i);
	return 0;
}
/*
   *cc13 get_free_block:
- *@sbi:指向超级块信息的指针实例
- *@seg_type:当前段的类型
- *@sit_lock:记录当前SIT表是否锁定
- *@return:返回当前块的页的起始位置
 */
static block_t get_free_block(struct hmfs_sb_info *sbi, int seg_type, 
				bool sit_lock)
{
	block_t page_addr = 0;
	/*
	 * SIT表的信息
	 */
	struct sit_info *sit_i = SIT_I(sbi);
	struct curseg_info *seg_i = &(CURSEG_I(sbi)[seg_type]);
	int ret;

	lock_curseg(seg_i);
	
	/*
	  *判断当前段的下一个块偏移是不是已经是块的最后
	 */
	if (seg_i->next_blkoff == HMFS_PAGE_PER_SEG) {
		/*
		*如果扫到块的尽头，则扫描下一个块
		 */
		ret = move_to_new_segment(sbi, seg_i);
		if (ret) {
			unlock_curseg(seg_i);
			return NULL_ADDR;
		}
	}

	page_addr = cal_page_addr(sbi, seg_i);
    /*
    *如果当前块为脏，，更新当前entry的位置
     */
	if (sit_lock)
		lock_sentry(sit_i);
	update_sit_entry(sbi, atomic_read(&seg_i->segno), 1);
	
	if (sit_lock)
		unlock_sentry(sit_i);
   /*
   * 继续移动到下面active的块的偏移位置
    */
	seg_i->next_blkoff++;

	unlock_curseg(seg_i);

	return page_addr;
}
/*
- * cc14 alloc_free_data_block:遍历当前active的数据
- * @sbi:指向超级块信息的指针实例
- * @return:遍历当前所有的超级块，依次移到下一个active的块
 */
block_t alloc_free_data_block(struct hmfs_sb_info * sbi)
{
	return get_free_block(sbi, CURSEG_DATA, true);
}
/*
 - *cc15 alloc_free_node_block：遍历当前active的node
- *@sbi:指向超级块信息的指针实例
- *@sit_lock：依次移到下一个active的块
 */
block_t alloc_free_node_block(struct hmfs_sb_info * sbi, bool sit_lock)
{
	return get_free_block(sbi, CURSEG_NODE, sit_lock);
}

/*
 - *cc16 recovery_sit_entries:从日志记录中恢复SIT入口块的信息
- *@sbi:指向超级块信息的指针实例
- *@hmfs_cp:管理检查点的实例
 */
void recovery_sit_entries(struct hmfs_sb_info *sbi,
				struct hmfs_checkpoint *hmfs_cp)
{
	int nr_logs, i, nr_segs, num = 0;
	struct hmfs_sit_log_entry *sit_log;
	struct hmfs_sit_entry *sit_entry;
	block_t seg_addr;
	/*
	 * 定义段号的类型
	 */
	seg_t sit_segno, segno;

	nr_logs = le16_to_cpu(hmfs_cp->nr_logs);
	nr_segs = hmfs_cp->nr_segs;
	for (i = 0; i < nr_segs; i++) {
		/*
		 *依次转化获取了SIT日志的段号，计算当前mainarea的段地址ַ
		 */
		sit_segno = le32_to_cpu(hmfs_cp->sit_logs[i]);
		seg_addr = __cal_page_addr(sbi, sit_segno, 0);
		sit_log = ADDR(sbi, seg_addr);
		/*
		  * 遍历完当前所有的检查点指向段，获取当前SIT的入口地址，用日志时间等信息更新entry信息
		 */
		while (num < nr_logs) {
			segno = le32_to_cpu(sit_log->segno);
			sit_entry = get_sit_entry(sbi, segno);
			sit_entry->mtime = sit_log->mtime;
			sit_entry->vblocks = sit_log->vblocks;
			
			num++;
			sit_log++;
			if (num % LOGS_ENTRY_PER_SEG == 0)
				break;
		}
	}
}
/*
 - *cc17 flush_sit_entries_rmcp:在删除一个检查点后更新SIT area的信息，刷新空闲SIT信息
- *@sbi:指向超级块信息的指针实例
 */
/* Update SIT area after deleting a checkpoint */
void flush_sit_entries_rmcp(struct hmfs_sb_info *sbi)
{
	struct sit_info *sit_i = SIT_I(sbi);
	/*
	 *记录当前超级块中主存区肿块的个数
	 */
	pgc_t total_segs = TOTAL_SEGS(sbi);
	struct hmfs_sit_entry *sit_entry;
	struct seg_entry *seg_entry;
	/*
	 * 获取当前脏的entry的bitmap
	 */
	unsigned long *bitmap = sit_i->dirty_sentries_bitmap;
	/*
	 *获取某个段里面指向4KB大小的块的入口以及没有有效块的段的实例
	 */
	struct hmfs_summary *summary;
	struct free_segmap_info *free_i = FREE_I(sbi);
	int i;
	int offset = 0;

	while(1) {
		offset = find_next_bit(bitmap, total_segs, offset);
		if (offset < total_segs) {
			/*
              *根据偏移和超级块信息获取段入口SIT缓存入口地址
			 */
			seg_entry = get_seg_entry(sbi, offset);
			sit_entry = get_sit_entry(sbi, offset);
			/*
			 * In recovery process, the valid blocks in original
			 * SIT area might be invalid. Because system might crash during
			 * writing SIT. Thus, we need to calculate valid blocks by
			 * scaning SSA area
			 */
			/*
			  * 如果系统崩溃，通过扫描SSA区域计算有效块的个数
			 */
			if (sbi->recovery_doing) {
				seg_entry->valid_blocks = 0;
				summary = get_summary_block(sbi, offset)->entries;
				for (i = 0; i < SUM_ENTRY_PER_BLOCK; i++, summary++) {
					if (get_summary_valid_bit(summary))
						seg_entry->valid_blocks++;
				}
			}
			/*
			*如果段的入口不是有效块，则记录空闲段的数量加1
			 */
			if (!seg_entry->valid_blocks) {
				lock_write_segmap(free_i);
				clear_bit(offset, free_i->free_segmap);
				free_i->free_segmap++;
				unlock_write_segmap(free_i);
			}

			seg_info_to_raw_sit(seg_entry, sit_entry);
			offset++;
		} else
			break;
	}
	sit_i->dirty_sentries = 0;
	memset_nt(sit_i->dirty_sentries_bitmap, 0, sit_i->bitmap_size);
}

/*
 *18cc: flush_sit_entries：刷新SIT表的entry信息
 *@sbi:指向超级块信息的指针实例
 */
void flush_sit_entries(struct hmfs_sb_info *sbi, block_t new_cp_addr,
				void *new_nat_root)
{
	/*
	 * 初始化SIT信息表的整体段信息指针，SIT entry，位图指针，日志entry，检查点，空闲段信息指针
	 */
	struct sit_info *sit_i = SIT_I(sbi);
	unsigned long offset = 0;
	pgc_t total_segs = TOTAL_SEGS(sbi);
	struct hmfs_sit_entry *sit_entry;
	struct seg_entry *seg_entry;
	unsigned long *bitmap = sit_i->dirty_sentries_bitmap;
	int nr_logs = 0, i = 0, nr_segs;
	struct hmfs_sit_log_entry *sit_log;
	struct hmfs_checkpoint *hmfs_cp = CM_I(sbi)->last_cp_i->cp;
	struct free_segmap_info *free_i = FREE_I(sbi);
	seg_t sit_segno;
	block_t seg_addr;
/*
 * 遍历所有段信息，记录并配置当前超级块实例中脏的块数
 */
#ifdef CONFIG_HMFS_DEBUG
	pgc_t nrdirty = 0;

	while (1) {
		offset = find_next_bit(bitmap, total_segs, offset);
		if (offset < total_segs)
			nrdirty++;
		else
			break;
		offset++;
	}
	offset = 0;
	hmfs_bug_on(sbi, nrdirty != sit_i->dirty_sentries);
#endif

	/* First, prepare free segments to store dirty sit logs */
	/*
	 *首先准备空闲的段来存储脏的SIT表日志信息
	 */
	nr_logs = sit_i->dirty_sentries;
	nr_segs = (nr_logs + LOGS_ENTRY_PER_SEG - 1) / LOGS_ENTRY_PER_SEG - 1;
	sit_segno = le32_to_cpu(hmfs_cp->cur_data_segno);
	do {
retry:
        /*
         * 找到空闲段里所有段里空闲的部分，并且记录保存了SIT日志的段的信息
         */
		sit_segno = find_next_zero_bit(free_i->free_segmap, total_segs,
							sit_segno);
		if (sit_segno >= total_segs) {
			sit_segno = 0;
			goto retry;
		}
		hmfs_cp->sit_logs[nr_segs--] = cpu_to_le32(sit_segno);
		sit_segno++;
	} while(nr_segs >= 0);

	/* Then, copy all dirty seg_entry to cp */
	/*
	 *拷贝所有脏的段entry到检查点，记录段的地址，根据地址计算SIT日志的地址，接着对下一个段进行相同的操作
	 */
	i = 0;
	nr_segs = 0;
	nr_logs = 0;
	sit_log = NULL;
	while (1) {
		offset = find_next_bit(bitmap, total_segs, offset);
		if (i == 0) {
			seg_addr = __cal_page_addr(sbi, 
							le32_to_cpu(hmfs_cp->sit_logs[nr_segs]), 0);
			sit_log = ADDR(sbi, seg_addr);
			i = LOGS_ENTRY_PER_SEG;
			nr_segs++;
		}
		/*
		 * 获取段的缓存entry,在SIT日志表,记录段entry的修改时间，同时记录有效的块，
		 */
		if (offset < total_segs) {
			seg_entry = get_seg_entry(sbi, offset);
			sit_log->segno = cpu_to_le32(offset);
			sit_log->mtime = cpu_to_le32(seg_entry->mtime);
			sit_log->vblocks = cpu_to_le32(seg_entry->valid_blocks);
			sit_log++;
			nr_logs++;
			i--;
			offset = offset + 1;
		} else
			break;
	}
	/*
	 * 同时更新检查点的日志信息和段信息
	 */
	offset = 0;
	hmfs_cp->nr_logs = cpu_to_le16(nr_logs);
	hmfs_cp->nr_segs = nr_segs;

	set_fs_state_arg_2(hmfs_cp, new_cp_addr);
	set_fs_state(hmfs_cp, HMFS_ADD_CP);

	/* Then, copy all dirty seg_entry to SIT area */
	/*
	 * 把所有脏的段的entry写到SIT域，获取SIT entry和缓存信息，将信息更新到段信息SIT表中
	 */
	while (1) {
		offset = find_next_bit(bitmap, total_segs, offset);
		if (offset < total_segs) {
			sit_entry = get_sit_entry(sbi, offset);
			seg_entry = get_seg_entry(sbi, offset);
			offset = offset + 1;
			seg_info_to_raw_sit(seg_entry, sit_entry);
		} else
			break;
	}

	/* Finally, set valid bit in SSA */
	/*
	 * 最后在SSA区域设置有效的字节，重置脏的entry的位图大小
	 */
	mark_block_valid(sbi, new_nat_root, ADDR(sbi, new_cp_addr));
	sit_i->dirty_sentries = 0;
	memset_nt(sit_i->dirty_sentries_bitmap, 0, sit_i->bitmap_size);
}
/*
 - *cc19 __set_test_and_inuse:处理并设置当前空闲段为未使用过
- *@sbi:指向超级块信息的指针实例
- *@segno:段号的类型
 */
static inline void __set_test_and_inuse(struct hmfs_sb_info *sbi,
				seg_t segno)
{
	struct free_segmap_info *free_i = FREE_I(sbi);

	lock_write_segmap(free_i);
	if (!test_and_set_bit(segno, free_i->free_segmap)) {
		free_i->free_segments--;
	}
	unlock_write_segmap(free_i);
}

/*
 * routines for build segment manager
 */
/*
  *20cc build_sit_info:
- *@sbi:指向超级块信息的指针实例
 *@return:
 */
static int build_sit_info(struct hmfs_sb_info *sbi)
{
	/*
	  * 定义检查点管理器的实例和检查点的实例
	 */
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct hmfs_checkpoint *hmfs_cp = cm_i->last_cp_i->cp;
	struct sit_info *sit_i;
	unsigned long long bitmap_size;

	/*
	 *为SIT信息表分配内存
	 */
	/* allocate memory for SIT information */
	sit_i = kzalloc(sizeof(struct sit_info), GFP_KERNEL);
	if (!sit_i)
		return -ENOMEM;
    /*
      * 获取段管理器下整个段的信息
     */
	SM_I(sbi)->sit_info = sit_i;

	sit_i->sentries = vzalloc(TOTAL_SEGS(sbi) * sizeof(struct seg_entry));
	if (!sit_i->sentries)
		return -ENOMEM;
    /*
     * 初始化当前脏的段的bitmap
     */
	bitmap_size = hmfs_bitmap_size(TOTAL_SEGS(sbi));
	sit_i->bitmap_size = bitmap_size;
	sit_i->dirty_sentries_bitmap = kzalloc(bitmap_size, GFP_KERNEL);
	if (!sit_i->dirty_sentries_bitmap)
		return -ENOMEM;

	memset_nt(sit_i->dirty_sentries_bitmap, 0, bitmap_size);

	sit_i->dirty_sentries = 0;

	/*
	 * 更新文件系统的生存时间和装载时间
	 */
	sit_i->elapsed_time = le32_to_cpu(hmfs_cp->elapsed_time);
	sit_i->mounted_time = CURRENT_TIME_SEC.tv_sec;
	/*
	  * 保护SIT的缓存
	 */
	mutex_init(&sit_i->sentry_lock);
	return 0;
}

/*
 *21cc free_prefree_segments:
 *@sbi:指向超级块信息的指针实例
 */
void free_prefree_segments(struct hmfs_sb_info *sbi)
{
	/*
	 * 定义空闲块的实例
	 */
	struct free_segmap_info *free_i = FREE_I(sbi);
	int total_segs = TOTAL_SEGS(sbi);
	unsigned long *bitmap = free_i->prefree_segmap;
	seg_t segno = 0;
	void *ssa;

	lock_write_segmap(free_i);
	while (1) {
		segno =find_next_bit(bitmap, total_segs, segno);
		if (segno >= total_segs)
			break;
		clear_bit(segno, bitmap);
		/*
		 *刷新所有空闲段的信息，并且计数加1
		 */
		if (test_and_clear_bit(segno, free_i->free_segmap)) {
			free_i->free_segments++;
		}
		/*
		  *根据当前段号获取SSA信息
		 */
		ssa = get_summary_block(sbi, segno);
		memset_nt(ssa, 0, HMFS_SUMMARY_BLOCK_SIZE);
		segno++;
	}
	unlock_write_segmap(free_i);
}
/*
 *cai22:build_free_segmap:生成空闲段的若干操作
 *@sbi:指向hmfs超级块信息的实例
 *@return:操作正确返回0，否则返回超出内存范围
 */
static int build_free_segmap(struct hmfs_sb_info *sbi)
{
	struct free_segmap_info *free_i;
	unsigned int bitmap_size;

	/* allocate memory for free segmap information */
	/*
	 * 回收GFP_KERNEL类型的内存空间
	 */
	free_i = kzalloc(sizeof(struct free_segmap_info), GFP_KERNEL);
	if (!free_i)
		/*
		 * 超出内存范围
		 */
		return -ENOMEM;
    /*
     *实例化当前超级块实例下的段管理器信息，将空段信息置为回收后的空间
     */
	SM_I(sbi)->free_info = free_i;
    /*
     *求main area段的大小，同时回收该段大小，同时实例化空段指针实例中的位图信息，如果有预留空间，返回预留空间
     */
	bitmap_size = hmfs_bitmap_size(TOTAL_SEGS(sbi));
	free_i->free_segmap = kmalloc(bitmap_size, GFP_KERNEL);
	if (!free_i->free_segmap) {
		goto free_i;
	}
	free_i->prefree_segmap = kmalloc(bitmap_size, GFP_KERNEL);
	if (!free_i->prefree_segmap)
		goto free_segmap;

	/* set all segments as dirty temporarily */
	/*
	 * 将所有的空闲段暂时置为脏
	 */
	memset(free_i->free_segmap, 0xff, bitmap_size);
	memset(free_i->prefree_segmap, 0, bitmap_size);

	/* init free segmap information */
	/*
	 *初始化空闲段的信息，同时初始化读写的锁
	 */
	free_i->free_segments = 0;
	rwlock_init(&free_i->segmap_lock);
	return 0;

free_segmap:
	kfree(free_i->free_segmap);
free_i:
	kfree(free_i);
	return -ENOMEM;
}

/*
 *cc23 build_curseg:
 *@sbi:指向hmfs超级块信息的实例
 *@return:操作正确返回0，否则返回超出内存范围
 */
static int build_curseg(struct hmfs_sb_info *sbi)
{
	/*
	 *定义active日志指针实例，初始化检查点的管理器信息，检查点
	 */
	struct curseg_info *array;
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct hmfs_checkpoint *hmfs_cp = cm_i->last_cp_i->cp;
	unsigned short node_blkoff, data_blkoff;

	/*
	 * 根据段日志分配内存大小
	 */
	array = kzalloc(sizeof(struct curseg_info) * NR_CURSEG_TYPE,
					GFP_KERNEL);
	if (!array)
		return -ENOMEM;

	SM_I(sbi)->curseg_array = array;

	/*
	 * 锁的一致性
	 */
	mutex_init(&array[CURSEG_NODE].curseg_mutex);
	mutex_init(&array[CURSEG_DATA].curseg_mutex);

    /*
     * 先锁定当前的段，并且将当前node段的信息，写下一个要写的段偏移，再解锁当前段，设置当前段信息，同时将下一个段先置为空
     */
	lock_curseg(&array[CURSEG_NODE]);
	node_blkoff = le16_to_cpu(hmfs_cp->cur_node_blkoff);
	array[CURSEG_NODE].next_blkoff = node_blkoff;
	atomic_set(&array[CURSEG_NODE].segno, le32_to_cpu(hmfs_cp->cur_node_segno));
	array[CURSEG_NODE].next_segno = NULL_SEGNO;
	unlock_curseg(&array[CURSEG_NODE]);

	/*
	 *将当前数据段的信息写到写到日志信息中，同时重复上述操作
	 */
	lock_curseg(&array[CURSEG_DATA]);
	data_blkoff = le16_to_cpu(hmfs_cp->cur_data_blkoff);
	array[CURSEG_DATA].next_blkoff = data_blkoff;
	atomic_set(&array[CURSEG_DATA].segno, le32_to_cpu(hmfs_cp->cur_data_segno));
	array[CURSEG_DATA].next_segno = NULL_SEGNO;
	unlock_curseg(&array[CURSEG_DATA]);

	return 0;
}

/*
 *cc24 build_sit_entries:重写SIT表entry的信息
 *@sbi:指向hmfs超级块信息的实例
 */
static void build_sit_entries(struct hmfs_sb_info *sbi)
{
	struct sit_info *sit_i = SIT_I(sbi);
	struct seg_entry *seg_entry;
	struct hmfs_sit_entry *sit_entry;
	unsigned int start;

	/*
	 *处理SIT的entry信息，获取当前段缓存entry和SIT表entry信息，用作SIT表entry信息的更新
	 */
	lock_sentry(sit_i);
	for (start = 0; start < TOTAL_SEGS(sbi); start++) {
		seg_entry = get_seg_entry(sbi, start);
		sit_entry = get_sit_entry(sbi, start);
		seg_info_from_raw_sit(seg_entry, sit_entry);
	}
	unlock_sentry(sit_i);
}

/*
 *cc25 init_free_segmap:根据当前超级块实例信息，初始化所有空闲段
 *@sbi:指向hmfs超级块信息的实例
 */
static void init_free_segmap(struct hmfs_sb_info *sbi)
{
	struct free_segmap_info *free_i = FREE_I(sbi);
	unsigned int start;
	struct curseg_info *curseg_t = NULL;
	struct seg_entry *sentry = NULL;
	int i;

	/*
	 * 对所有的段，先获取段的入口地址，接下来释放所有空闲的段中失效的块所占有的空间
	 */
	for (start = 0; start < TOTAL_SEGS(sbi); start++) {
		sentry = get_seg_entry(sbi, start);
		if (!sentry->valid_blocks) {
			lock_write_segmap(free_i);
			clear_bit(start, free_i->free_segmap);
			free_i->free_segments++;
			unlock_write_segmap(free_i);
		}
	}

	/* set use the current segments */
	/*
	 *处理当前active的段信息
	 */
	curseg_t = CURSEG_I(sbi);
	for (i = 0; i < NR_CURSEG_TYPE; i++)
		__set_test_and_inuse(sbi, atomic_read(&curseg_t[i].segno));
}

static void init_dirty_segmap(struct hmfs_sb_info *sbi)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	struct free_segmap_info *free_i = FREE_I(sbi);
	struct curseg_info *curseg_t = CURSEG_I(sbi);
	seg_t segno, total_segs = TOTAL_SEGS(sbi), offset = 0;
	unsigned short valid_blocks;
	int i;

	while (1) {
		/* find dirty segmap based on free segmap */
		segno = find_next_inuse(free_i, total_segs, offset);
		if (segno >= total_segs)
			break;
		offset = segno + 1;
		valid_blocks = get_seg_entry(sbi, segno)->valid_blocks;
		if (valid_blocks >= HMFS_PAGE_PER_SEG || !valid_blocks)
			continue;
		test_and_set_bit(segno, dirty_i->dirty_segmap);
	}

	/* Clear the current segments */
	for (i = 0; i < NR_CURSEG_TYPE; i++)
		clear_bit(atomic_read(&curseg_t[i].segno), dirty_i->dirty_segmap);
}

static int build_dirty_segmap(struct hmfs_sb_info *sbi)
{
	struct dirty_seglist_info *dirty_i;
	unsigned int bitmap_size;

	dirty_i = kzalloc(sizeof(struct dirty_seglist_info), GFP_KERNEL);
	if (!dirty_i)
		return -ENOMEM;

	SM_I(sbi)->dirty_info = dirty_i;

	bitmap_size = (BITS_TO_LONGS(TOTAL_SEGS(sbi)) * sizeof(unsigned long));

	dirty_i->dirty_segmap = kzalloc(bitmap_size, GFP_KERNEL);

	if (!dirty_i->dirty_segmap)
		return -ENOMEM;

	init_dirty_segmap(sbi);
	return 0;
}

int build_segment_manager(struct hmfs_sb_info *sbi)
{
	struct hmfs_super_block *raw_super = HMFS_RAW_SUPER(sbi);
	struct hmfs_sm_info *sm_info;
	int err;
	pgc_t user_segments, main_segments;

	sm_info = kzalloc(sizeof(struct hmfs_sm_info), GFP_KERNEL);
	if (!sm_info)
		return -ENOMEM;

	/* init sm info */
	sbi->sm_info = sm_info;
	sm_info->segment_count = le64_to_cpu(raw_super->segment_count);
	main_segments = le64_to_cpu(raw_super->segment_count_main);
	sm_info->main_segments = main_segments;
	user_segments = sm_info->main_segments * (100 - DEF_OP_SEGMENTS) / 100;
	sm_info->ovp_segments = sm_info->main_segments - user_segments;
	sm_info->limit_invalid_blocks = main_segments * HMFS_PAGE_PER_SEG
			* LIMIT_INVALID_BLOCKS / 100;
	sm_info->limit_free_blocks = main_segments * HMFS_PAGE_PER_SEG 
			* LIMIT_FREE_BLOCKS / 100;
	sm_info->severe_free_blocks = main_segments * HMFS_PAGE_PER_SEG 
			* SEVERE_FREE_BLOCKS / 100;

	err = build_sit_info(sbi);
	if (err)
		return err;
	err = build_free_segmap(sbi);
	if (err)
		return err;
	err = build_curseg(sbi);
	if (err)
		return err;

	/* reinit free segmap based on SIT */
	build_sit_entries(sbi);

	init_free_segmap(sbi);
	err = build_dirty_segmap(sbi);
	if (err)
		return err;

	init_min_max_mtime(sbi);
	return 0;
}

static void destroy_dirty_segmap(struct hmfs_sb_info *sbi)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);

	if (!dirty_i)
		return;

	kfree(dirty_i->dirty_segmap);

	SM_I(sbi)->dirty_info = NULL;
	kfree(dirty_i);
}

static void destroy_curseg(struct hmfs_sb_info *sbi)
{
	struct curseg_info *array = SM_I(sbi)->curseg_array;

	if (!array)
		return;
	SM_I(sbi)->curseg_array = NULL;
	kfree(array);
}

static void destroy_free_segmap(struct hmfs_sb_info *sbi)
{
	struct free_segmap_info *free_i = SM_I(sbi)->free_info;

	if (!free_i)
		return;
	SM_I(sbi)->free_info = NULL;
	kfree(free_i->free_segmap);
	kfree(free_i->prefree_segmap);
	kfree(free_i);
}

static void destroy_sit_info(struct hmfs_sb_info *sbi)
{
	struct sit_info *sit_i = SIT_I(sbi);

	if (!sit_i)
		return;

	vfree(sit_i->sentries);
	kfree(sit_i->dirty_sentries_bitmap);

	SM_I(sbi)->sit_info = NULL;
	kfree(sit_i);
}

void destroy_segment_manager(struct hmfs_sb_info *sbi)
{
	struct hmfs_sm_info *sm_info = SM_I(sbi);
	
	destroy_dirty_segmap(sbi);
	destroy_curseg(sbi);
	destroy_free_segmap(sbi);
	destroy_sit_info(sbi);
	sbi->sm_info = NULL;
	kfree(sm_info);
}

struct hmfs_summary_block *get_summary_block(struct hmfs_sb_info *sbi,
				seg_t segno)
{
	struct hmfs_summary_block *summary_blk;
	
	summary_blk = HMFS_SUMMARY_BLOCK(sbi->ssa_entries);
	return &summary_blk[segno];
}

struct hmfs_summary *get_summary_by_addr(struct hmfs_sb_info *sbi,
				block_t blk_addr)
{
	seg_t segno;
	unsigned int blkoff;
	struct hmfs_summary_block *summary_blk = NULL;

	segno = GET_SEGNO(sbi, blk_addr);
	blkoff = GET_SEG_OFS(sbi, blk_addr);
	summary_blk = get_summary_block(sbi, segno);

	return &summary_blk->entries[blkoff];
}
