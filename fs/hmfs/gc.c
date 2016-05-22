#include <linux/fs.h>
#include <linux/kthread.h>
#include <linux/freezer.h>

#include "hmfs.h"
#include "hmfs_fs.h"
#include "gc.h"
#include "segment.h"
#include "node.h"
#include "xattr.h"

/*
 * Setup arguments for GC and GC recovery
 */
/*
 *cc1 prepare_move_argument：为垃圾收集及垃圾收集的恢复设置并初始化参数
 *@arg：初始化参数实例
 *@sbi:指向超级块信息的指针实例
 *@mv_segno:段号
 *@mv_offset：偏移量
 *@sum：summary的地址参数
 *@type:段的数据类型
 */
/**
 * prepare_move_argument：为垃圾收集及垃圾收集的恢复设置并初始化参数
 * @param[in]    sbi     指向超级块信息的指针实例
 * @param[in]    arg     初始化参数实例
 * @param[in]    mv_segno  段号
 * @param[in]    mv_offset 偏移量
 * @param[in]    sum       summary的地址参数
 * @param[in]    type      段的数据类型
 * @ref          gc.h,node.h,segment.h,xattr.h,hmfs.h，hmfs_fs.h
 * @see
 * @note
 */
void prepare_move_argument(struct gc_move_arg *arg,
				struct hmfs_sb_info *sbi, seg_t mv_segno, unsigned mv_offset,
				struct hmfs_summary *sum, int type)
{
	/**
	 * 根据summary获取起始版本号，初始化参数的开始版本，nodeid,起始偏移量
	 */
	arg->start_version = get_summary_start_version(sum);
	arg->nid = get_summary_nid(sum);
	arg->ofs_in_node = get_summary_offset(sum);
	/**
	 * 根据超级块的段的偏移量计算当前偏移地址，初始化参数中的指针所指向的地址
	 */
	arg->src_addr = __cal_page_addr(sbi, mv_segno, mv_offset);
	arg->src = ADDR(sbi, arg->src_addr);
    /**
     * 根据起始版本信息，获取检查点信息
     */
	arg->cp_i = get_checkpoint_info(sbi, arg->start_version, true);

	/**
	 * 判断是否需要进行修复
	 */
	if (sbi->recovery_doing)
		return;

	/**
	 * 目标指针指向分配的新的数据块和节点的空间
	 */
	if (type == TYPE_DATA) {
		arg->dest = alloc_new_data_block(sbi, NULL, 0);
	} else {
		arg->dest = alloc_new_node(sbi, 0, NULL, 0, true);
	}
	
	hmfs_bug_on(sbi, IS_ERR(arg->dest));

	/**
	 *地址转换后返回目的地址，根据地址返回目的summary表
	 */
	arg->dest_addr = L_ADDR(sbi, arg->dest);
	arg->dest_sum = get_summary_by_addr(sbi, arg->dest_addr);
	
	/**
	 * 将数据从源地址复制到目的地址
	 */
	hmfs_memcpy(arg->dest, arg->src, HMFS_PAGE_SIZE);
}

/*
 *2cc get_cb_cost：返回得到回收当前SIT中段的时间开销
 *@sbi:指向超级块信息的指针实例
 *@segno:段号
 */
/**
 * get_cb_cost：返回得到回收当前SIT中段的时间开销
 * @param[in]    sbi     指向超级块信息的指针实例
 * @param[in]    segno   段号
 * @return       返回值
 * @ref         gc.h,node.h,segment.h,xattr.h,hmfs.h，hmfs_fs.h
 * @see
 * @note
 */
static unsigned int get_cb_cost(struct hmfs_sb_info *sbi, unsigned int segno)
{

	struct sit_info *sit_i = SIT_I(sbi);
	unsigned long long mtime = 0;
	unsigned int vblocks;
	unsigned char age = 0;
	unsigned char u;

	/**
	 * 初始化段entry的修改时间和有效块的个数
	 */
	mtime = get_seg_entry(sbi, segno)->mtime;
	vblocks = get_seg_entry(sbi, segno)->valid_blocks;

	u = (vblocks * 100) >> HMFS_PAGE_PER_SEG_BITS;

	/**
	 * 更新SIT表的最小和最大修改时间为最新，如果最小时间大于最大时间，则更新SIT表的age
	 */
	if (mtime < sit_i->min_mtime)
		sit_i->min_mtime = mtime;
	if (mtime > sit_i->max_mtime)
		sit_i->max_mtime = mtime;
	if (sit_i->max_mtime != sit_i->min_mtime)
		age = 100 - div64_u64(100 * (mtime - sit_i->min_mtime),
			     			sit_i->max_mtime - sit_i->min_mtime);

	return UINT_MAX - ((100 * (100 - u) * age) / (100 + u));
}
/*
 * cc3 get_max_cost:返回要遍历的段的大小
 * @sbi:指向超级块信息的指针实例
 * @p:记录块回收的实例
 * @return:返回要遍历的段的大小
 */
/**
 * get_max_cost:返回要遍历的段的大小
 * @param[in]    sbi     指向超级块信息的指针实例
 * @param[in]    p       记录块回收的实例
 * @return       返回要遍历的段的大小
 * @ref          gc.h,node.h,segment.h,xattr.h,hmfs.h，hmfs_fs.h
 * @see
 * @note
 */
static unsigned int get_max_cost(struct hmfs_sb_info *sbi,
				 struct victim_sel_policy *p)
{
	/**
	 *如果垃圾回收的类型是贪婪类型，则从头遍历段的大小，即2M的段大小
	 */
	if (p->gc_mode == GC_GREEDY)
		return HMFS_PAGE_PER_SEG;
	else if (p->gc_mode == GC_CB)
		return UINT_MAX;
	else
		return 0;
}
/*
 *cc4 get_gc_cost:通过该段的入口地址返回有效的块的个数
 *@sbi:指向超级块信息的指针实例
 *@p:记录块回收的实例
 */
/**
 * get_gc_cost:通过该段的入口地址返回有效的块的个数
 * @param[in]    sbi     指向超级块信息的指针实例
 * @param[in]    p       记录块回收的实例
 * @return       返回值
 * @ref          gc.h,node.h,segment.h,xattr.h,hmfs.h，hmfs_fs.h
 * @see
 * @note
 */
static unsigned int get_gc_cost(struct hmfs_sb_info *sbi, unsigned int segno,
				struct victim_sel_policy *p)
{
//	if (p->gc_mode == GC_GREEDY)
		return get_seg_entry(sbi, segno)->valid_blocks;
//	else
//		return get_cb_cost(sbi, segno);
}

/*
 * Select a victim segment from dirty_segmap. We don't lock dirty_segmap here.
 * Because we could tolerate somewhat inconsistency of it. start_segno is used
 * for FG_GC, i.e. we scan the whole space of NVM atmost once in a FG_GC. Therefore,
 * we take down the first victim segment as start_segno
 */
//TODO: We might need to collect many segments in one victim searching
/*
 *cc5 get_victim：
 *@sbi:指向超级块信息的指针实例
 *@gc_type:垃圾回收的类型
 */
/**
 * get_victim：
 * @param[in]    sbi     指向超级块信息的指针实例
 * @param[in]    gc_type 垃圾回收的类型
 * @return       返回是否是被选中为回收段的标识
 * @ref          gc.h,node.h,segment.h,xattr.h,hmfs.h，hmfs_fs.h
 * @see
 * @note
 */
static int get_victim(struct hmfs_sb_info *sbi, seg_t *result, int gc_type)
{
	/**
	 *定义脏的段的实例，检查点的实例
	 */
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	struct hmfs_checkpoint *hmfs_cp = CM_I(sbi)->last_cp_i->cp;
	struct victim_sel_policy p;
	unsigned int max_cost;
	unsigned long cost;
	seg_t segno;
	int nsearched = 0;
	int total_segs = TOTAL_SEGS(sbi);
	/**
	 * 定义当前记录的日志信息中段的情况
	 */
	struct curseg_info *seg_i0 = &(CURSEG_I(sbi)[0]);
	struct curseg_info *seg_i1 = &(CURSEG_I(sbi)[1]);

	/**
	 *判断得到当前垃圾回收的类型，根据上一次垃圾回收时victim类型返回当前偏移量，以及返回当前便利的段的开销
	 */
	p.gc_mode = gc_type == BG_GC ? GC_CB : GC_GREEDY;
	p.offset = sbi->last_victim[p.gc_mode];
	p.min_segno = NULL_SEGNO;
	p.min_cost = max_cost = get_max_cost(sbi, &p);

	while (1) {
		/**
		 *根据脏段的为题情况，偏移量等找到下一个脏的段
		 */
		segno = find_next_bit(dirty_i->dirty_segmap, total_segs, p.offset);

		if (segno >= total_segs) {
			/**
			 *如果垃圾回收的类型是贪婪的，就更新偏移量和类型，否则遍历下一个段
			 */
			if (sbi->last_victim[p.gc_mode]) {
				sbi->last_victim[p.gc_mode] = 0;
				p.offset = 0;
				continue;
			}
			break;
		} else {
			p.offset = segno + 1;
		}

		if (segno == atomic_read(&seg_i0->segno) || 
					segno == atomic_read(&seg_i1->segno)) {
			continue;
		}

		/*
		 * It's not allowed to move node segment where last checkpoint
		 * locate. Because we need to log GC segments in it.
		 */
		/**
		 *不移动node段的信息，根据上一次检查点的位置
		 */
		if (segno == le32_to_cpu(hmfs_cp->cur_node_segno)) {
			continue;
		}

		/* Stop if we find a segment whose cost is small enough */
		/**
		 * 如果某段有效块的个数少于100，即开销很小，则对回收类型进行定义
		 */
		if (get_seg_entry(sbi, segno)->valid_blocks < NR_GC_MIN_BLOCK) {
			p.min_segno = segno;
			hmfs_dbg("Get victim:%lu vblocks:%d gc_type:%s\n", (unsigned long)segno, get_seg_entry(sbi, segno)->valid_blocks,
					gc_type == BG_GC ? "BG" : "FG");
			break;
		}

		cost = get_gc_cost(sbi, segno, &p);
	//	hmfs_dbg("%lu %lu %s\n", (unsigned long)segno, cost, gc_type == BG_GC ? "BG" : "FG");
		/**
		 *如果当前开销低于记录的最低开销，则更新，并且寻找下一块
		 */
		if (p.min_cost > cost) {
			p.min_segno = segno;
			p.min_cost = cost;
		}

		if (cost == max_cost)
			continue;

		if (nsearched++ >= MAX_SEG_SEARCH) {
			break;
		}
	}

	sbi->last_victim[p.gc_mode] = segno;

	if (p.min_segno != NULL_SEGNO) {
		*result = p.min_segno;
	}
	/**
	 * 判断是否是空段。
	 */
	hmfs_dbg("Select %d\n", p.min_segno == NULL_SEGNO ? -1 : p.min_segno);
	return (p.min_segno == NULL_SEGNO) ? 0 : 1;
}
/*
 *cc6 update_dest_summary:复制块
 *@src_sum:段中大小是4KB的块summary entry实例，作为源块
 *@dest_sum:段中大小是4KB的块summary entry实例，作为目的块
 */
/**
 * update_dest_summary:复制块
 * @param[in]    src_sum:段中大小是4KB的块summary entry实例，作为源块
 * @param[in]    dest_sum:段中大小是4KB的块summary entry实例，作为目的块
 * @ref          gc.h,node.h,segment.h,xattr.h,hmfs.h，hmfs_fs.h
 * @see
 * @note
 */
static void update_dest_summary(struct hmfs_summary *src_sum,
				struct hmfs_summary *dest_sum)
{
	hmfs_memcpy(dest_sum, src_sum, sizeof(struct hmfs_summary));
}

/*
 *cc7 move_data_block:
 *@sbi:指向超级块信息的指针实例
 *@src_segno:源段号类型
 *@src_off：
 *@src_sum:summary entry的实例
 */
/**
 * move_data_block:移动数据块
 * @param[in]    sbi     指向超级块信息的指针实例
 * @param[in]    src_segno 源段号类型
 * @param[in]    src_off 源地址
 * @ref          gc.h,node.h,segment.h,xattr.h,hmfs.h，hmfs_fs.h
 * @see
 * @note
 */
static void move_data_block(struct hmfs_sb_info *sbi, seg_t src_segno,
			    int src_off, struct hmfs_summary *src_sum)
{
	/**
	 * 检查点管理器的实例
	 */
	struct gc_move_arg args;
	struct hmfs_node *last = NULL, *this = NULL;
	struct hmfs_summary *par_sum = NULL;
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	bool is_current;
	block_t addr_in_par;
	int par_type;

	/**
	 *根据summary入口信息获取版本信息，并且判断是否等于检查点管理器记录的最新版本
	 */
	is_current = get_summary_start_version(src_sum) == cm_i->new_version;

	/* 1. read summary of source blocks */
	/* 2. move blocks */
	/**
	 *为垃圾回收准备参数
	 */
	prepare_move_argument(&args, sbi, src_segno, src_off, src_sum,
			TYPE_DATA);

	while (1) {
		/* 3. get the parent node which hold the pointer point to source node */
		/**
		 *得到指向段节点的node的父节点
		 */
		this = __get_node(sbi, args.cp_i, args.nid);

		par_sum = get_summary_by_addr(sbi, L_ADDR(sbi, this));

		/**
		 * 判断该节点是否已经被删除
		 */
		if (IS_ERR(this)) {
			/* the node(args.nid) has been deleted */
			break;
		}


		hmfs_dbg_on(get_summary_type(par_sum) != SUM_TYPE_INODE &&
				get_summary_type(par_sum) != SUM_TYPE_DN, "Invalid summary type:"
				" nid(%u) Address(%p)[%lu %d] Version(%d) Type(%d)\n", args.nid, 
				par_sum, GET_SEGNO(sbi, L_ADDR(sbi, this)), GET_SEG_OFS(sbi, L_ADDR(sbi, this)), 
				args.cp_i->version, get_summary_type(par_sum));

		hmfs_bug_on(sbi, get_summary_type(par_sum) != SUM_TYPE_INODE &&
				get_summary_type(par_sum) != SUM_TYPE_DN);

		/* Now the pointer contains in direct node have been changed last time */
		/**
		 *判断直接节点里的指针是否已经被修改了
		 */
		if (this == last)
			goto next;

		par_type = get_summary_type(par_sum);

		/* Now src data block has been COW or parent node has been removed */
		/**
		 *判断父节点的类型是否是inode的块
		 */
		if (par_type == SUM_TYPE_INODE) {
			addr_in_par = le64_to_cpu(this->i.i_addr[args.ofs_in_node]);
		} else {
			addr_in_par = le64_to_cpu(this->dn.addr[args.ofs_in_node]);
		}

		/*
		 * In normal GC, we should stop when addr_in_par != src_addr,
		 * now direct node or inode in laster checkpoint would never
		 * refer to this data block
		 */
		/**
		 *在正常的垃圾回收的过程中，如果父节点的块类型等于了源类型，就停止。因为后来的检查点中的直接节点和inode一定不会指向这个数据块
		 */
		if (addr_in_par != args.src_addr) 
			break;

		/* 
		 * We should use atomic write here, otherwise, if system crash
		 * during wrting address, i.i_addr and dn.addr would be invalid,
		 * whose value is neither args.dest_addr nor args.src_addr. Therefore,
		 * if recovery process, it would terminate in this checkpoint
		 */
		/**
		 *如果系统崩溃了，在写地址的时候，i.i_addr和dn.addr都会是无效的，所以应该用原子写，因此，如果是恢复过程，在检查点钟将会终止
		 */
		if (par_type == SUM_TYPE_INODE) {
			hmfs_memcpy_atomic(&this->i.i_addr[args.ofs_in_node], 
					&args.dest_addr, 8);
		} else {
			hmfs_memcpy_atomic(&this->dn.addr[args.ofs_in_node],
					&args.dest_addr, 8);
		}
		
		last = this;

next:
		/* cp_i is the lastest checkpoint, stop */
       /**
        * 判断当前检查点是否是最新的检查点，如果是，则停止
        */
		if (args.cp_i == cm_i->last_cp_i || is_current) {
			break;
		}
		args.cp_i = get_next_checkpoint_info(sbi, args.cp_i);
	}

	/* 5. Update summary infomation of dest block */
	/**
	 * 更新目标块的summary信息
	 */
	update_dest_summary(src_sum, args.dest_sum);
}

/*
 * cc8 recycle_segment:回收无效的段
 * @sbi:指向超级块信息的指针实例
 * @segno:段号类型
 * @none_valid:判断块是否无效
 */
/**
 * recycle_segment:回收无效的段
 * @param[in]    sbi     指向超级块信息的指针实例
 * @param[in]    segno   段号类型
 * @param[in]    none_valid 判断块是否无效
 * @ref          gc.h,node.h,segment.h,xattr.h,hmfs.h，hmfs_fs.h
 * @see
 * @note
 */
static void recycle_segment(struct hmfs_sb_info *sbi, seg_t segno, bool none_valid)
{
	struct sit_info *sit_i = SIT_I(sbi);
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct free_segmap_info *free_i = FREE_I(sbi);
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	struct seg_entry *seg_entry;

	/**
	 *根据SIT表信息先锁定入口
	 */
	lock_sentry(sit_i);

	/* clean dirty bit */
	/**
	 *根据SIT表中脏段的位图信息，清理脏的sentries,同时初始化有效的块数和时间
	 */
	if (!test_and_set_bit(segno, sit_i->dirty_sentries_bitmap)) {
		sit_i->dirty_sentries++;
	}
	seg_entry = get_seg_entry(sbi, segno);
	seg_entry->valid_blocks = 0;
	seg_entry->mtime = get_seconds();

	unlock_sentry(sit_i);

	/* clear dirty bit */
	/**
	 * 清理脏的比特
	 */
	if (!test_and_clear_bit(segno, dirty_i->dirty_segmap))
		hmfs_bug_on(sbi, 1);

	/**
	 * 如果是无效的块，锁定写的段位图，，遍历并清理所有空闲段的信息
	 */
	if (none_valid) {
		lock_write_segmap(free_i);
		if (test_and_clear_bit(segno, free_i->free_segmap)) {
			free_i->free_segments++;
		}
		unlock_write_segmap(free_i);
	} else {
		/* set prefree bit */
		/**
		 *测试所有无效块的空闲段信息
		 */
		if (test_and_set_bit(segno, free_i->prefree_segmap))
			hmfs_bug_on(sbi, 1);
	}

	/* Now we have recycle HMFS_PAGE_PER_SEG blocks and update cm_i */
	/**
	 *现在根据检查点管理器清理每个段的中无效的段，同时更新检查点管理器
	 */
	lock_cm(cm_i);
	cm_i->alloc_block_count -= HMFS_PAGE_PER_SEG;
	unlock_cm(cm_i);
}

/*
 *cc 9 move_xdata_block:移动并更新数据块信息
 *@sbi:指向超级块信息的指针实例
 *@src_segno：源段号类型
 *@src_sum：源summary信息
 */
/**
 * move_xdata_block:移动并更新数据块信息
 * @param[in]    sbi     指向超级块信息的指针实例
 * @param[in]    src_segno：源段号类型
 * @param[in]    src_sum：源summary信息
 * @ref          gc.h,node.h,segment.h,xattr.h,hmfs.h，hmfs_fs.h
 * @see
 * @note
 */
static void move_xdata_block(struct hmfs_sb_info *sbi, seg_t src_segno,
				int src_off, struct hmfs_summary *src_sum)
{
	struct gc_move_arg arg;
	struct hmfs_node *last = NULL, *this = NULL;
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	block_t addr_in_par;
	int x_tag;
	bool is_current;
	
	is_current = get_summary_start_version(src_sum) == cm_i->new_version;

	prepare_move_argument(&arg, sbi, src_segno, src_off, src_sum,
			TYPE_DATA);

	while(1) {
		/**
		 * 根据检查点和node id获取这个阶段，判断这个节点是否被删除了
		 */
		this = __get_node(sbi, arg.cp_i, arg.nid);

		if (IS_ERR(this))
			break;

		hmfs_bug_on(sbi, get_summary_type(get_summary_by_addr(sbi, L_ADDR(sbi, this)))
				!= SUM_TYPE_INODE);

		if (this == last)
			goto next;

		x_tag = le64_to_cpu(XATTR_HDR(arg.src)->h_magic);
		addr_in_par = XBLOCK_ADDR(this, x_tag);
		
		/**
		 *判断当前地址是否等于源地址
		 */
		if (addr_in_par != arg.src_addr) {
			break;
		}
		/**
		 *copy调至源类型
		 */
		hmfs_memcpy_atomic(JUMP(this, x_tag), &arg.dest_addr, 8);

		last = this;

next:
		if (arg.cp_i == cm_i->last_cp_i || is_current)
			break;
		/**
		 * 判断当前检查点是否等于下一个检查点
		 */
		arg.cp_i = get_next_checkpoint_info(sbi, arg.cp_i);
	}
    /**
     *用目的summary信息更新源summary信息
     */
	update_dest_summary(src_sum, arg.dest_sum);
}
/*
 *cc10 move_node_block:移动node块信息
 *@sbi:指向超级块信息的指针实例
 *@src_segno：源段号类型
 *@src_sum：源summary信息
 */
/**
 * move_node_block:移动node块信息
 * @param[in]    sbi     指向超级块信息的指针实例
 * @param[in]    src_segno  源段号类型
 * @param[in]    src_sum  源summary信息
 * @ref          gc.h,node.h,segment.h,xattr.h,hmfs.h，hmfs_fs.h
 * @see
 * @note
 */
static void move_node_block(struct hmfs_sb_info *sbi, seg_t src_segno,
			    unsigned int src_off, struct hmfs_summary *src_sum)
{
	struct hmfs_nat_block *last = NULL, *this = NULL;
	struct gc_move_arg args;
	block_t addr_in_par;
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	bool is_current;

	is_current = get_summary_start_version(src_sum) == cm_i->new_version;

	prepare_move_argument(&args, sbi, src_segno, src_off, src_sum, TYPE_NODE);

	if (is_current) {
		//update NAT cache
		/**
		 * 更新NAT缓存信息
		 */
		gc_update_nat_entry(NM_I(sbi), args.nid, args.dest_addr);
		return;
	}

	while (1) {
		/**
		 *根据检查点的版本和node id获取NAT表的入口块信息
		 */
		this = get_nat_entry_block(sbi, args.cp_i->version, args.nid);
		if (IS_ERR(this))
			break;

		if (this == last)
			goto next;

		addr_in_par = le64_to_cpu(this->entries[args.ofs_in_node].block_addr);
		/* Src node has been COW or removed */
		/**
		 *判断源节点是否已经删除
		 */
		if (addr_in_par != args.src_addr) {
			break;
		}

		hmfs_memcpy_atomic(&this->entries[args.ofs_in_node].block_addr,
				&args.dest_addr, 8);
		last = this;

next:
       /**
        *判断当前检查点是否和上一次的检查点相同
        */
		if (args.cp_i == CM_I(sbi)->last_cp_i)
			break;
		args.cp_i = get_next_checkpoint_info(sbi, args.cp_i);
	}

	update_dest_summary(src_sum, args.dest_sum);
}
/*
 *cc11 move_nat_block:移动NAT块
 *@sbi:指向超级块信息的指针实例
 *@src_segno：源段号类型
 *@src_sum：源summary信息
 */
/**
 * move_nat_block:移动NAT块
 * @param[in]    sbi     指向超级块信息的指针实例
 * @param[in]    src_segno  源段号类型
 * @param[in]    src_sum  源summary信息
 * @ref          gc.h,node.h,segment.h,xattr.h,hmfs.h，hmfs_fs.h
 * @see
 * @note
 */
static void move_nat_block(struct hmfs_sb_info *sbi, seg_t src_segno, int src_off,
			   struct hmfs_summary *src_sum)
{
	void *last = NULL, *this = NULL;
	struct hmfs_checkpoint *hmfs_cp;
	struct hmfs_nat_node *nat_node;
	struct gc_move_arg args;
	nid_t par_nid;
	block_t addr_in_par;

	prepare_move_argument(&args, sbi, src_segno, src_off, src_sum, TYPE_NODE);

	while (1) {
		/**
		 *根据节点ID判断是否为NAT表的根节点，如果是，更新检查点信息，如果不是，更新父节点信息，同时获取指向NAT表节点的实例
		 */
		if (IS_NAT_ROOT(args.nid))
			this = args.cp_i->cp;
		else {
			par_nid = MAKE_NAT_NODE_NID(GET_NAT_NODE_HEIGHT(args.nid) - 1, 
							GET_NAT_NODE_OFS(args.nid)); 
			this = get_nat_node(sbi, args.cp_i->version, par_nid);
		}

		hmfs_bug_on(sbi, !this);
		if (this == last)
			goto next;

		/**
		 *判断是否是NAT表的根节点。判断是否是NAT表的根节点，同时更新检查点和父节点地址信息
		 */
		if (IS_NAT_ROOT(args.nid)) {
			hmfs_cp = HMFS_CHECKPOINT(this);
			addr_in_par = le64_to_cpu(hmfs_cp->nat_addr);
		} else {
			nat_node = HMFS_NAT_NODE(this);
			addr_in_par = le64_to_cpu(nat_node->addr[args.ofs_in_node]);
		}

		if (addr_in_par != args.src_addr) {
			break;
		}
		/**
		 *写入地址信息到NAT节点表中
		 */

		if (IS_NAT_ROOT(args.nid)) {
			hmfs_memcpy_atomic(&hmfs_cp->nat_addr, &args.dest_addr, 8);
		} else {
			hmfs_memcpy_atomic(&nat_node->addr[args.ofs_in_node], 
					&args.dest_addr, 8);
		}

		last = this;

next:
		if (args.cp_i == CM_I(sbi)->last_cp_i)
			break;
		args.cp_i = get_next_checkpoint_info(sbi, args.cp_i);
	}

	update_dest_summary(src_sum, args.dest_sum);
}

/* Orphan blocks is not shared */
/*
 *cc12 move_orphan_block:移动孤立的块
 *@sbi:指向超级块信息的指针实例
 *@src_segno：源段号类型
 *@src_sum：源summary信息
 */
/**
 * move_orphan_block:移动孤立的块
 * @param[in]    sbi     指向超级块信息的指针实例
 * @param[in]    src_segno  源段号类型
 * @param[in]    src_sum  源summary信息
 * @ref          gc.h,node.h,segment.h,xattr.h,hmfs.h，hmfs_fs.h
 * @see
 * @note
 */
static void move_orphan_block(struct hmfs_sb_info *sbi, seg_t src_segno, 
				int src_off, struct hmfs_summary *src_sum)
{
	struct gc_move_arg args;
	struct hmfs_checkpoint *hmfs_cp;
	block_t cp_addr;
	prepare_move_argument(&args, sbi, src_segno, src_off, src_sum,
			TYPE_NODE);
	cp_addr = le64_to_cpu(*((__le64 *)args.src));
	/**
	 *初始化检查点的地址信息，以及孤立点的信息
	 */
	hmfs_cp = ADDR(sbi, cp_addr);
	hmfs_cp->orphan_addrs[get_summary_offset(src_sum)] = 
			cpu_to_le64(args.dest_addr);

	update_dest_summary(src_sum, args.dest_sum);
}
/*
 *cc13 move_checkpoint_block:迁移检查点块
 *@sbi:指向超级块信息的指针实例
 *@src_segno：源段号类型
 *@src_sum：源summary信息
 */
/**
 * move_checkpoint_block:迁移检查点块
 * @param[in]    sbi     指向超级块信息的指针实例
 * @param[in]    src_segno  源段号类型
 * @param[in]    src_sum  源summary信息
 * @ref          gc.h,node.h,segment.h,xattr.h,hmfs.h，hmfs_fs.h
 * @see
 * @note
 */
static void move_checkpoint_block(struct hmfs_sb_info *sbi, seg_t src_segno,
				int src_off, struct hmfs_summary *src_sum)
{
	struct gc_move_arg args;
	struct hmfs_checkpoint *prev_cp, *next_cp, *this_cp;
	struct checkpoint_info *cp_i;
	int i;
	block_t orphan_addr;
	__le64 *orphan;

	prepare_move_argument(&args, sbi, src_segno, src_off, src_sum,
			TYPE_NODE);
	/**
	 *获取当前检查点信息
	 */

	cp_i = get_checkpoint_info(sbi, args.start_version, false);
	hmfs_bug_on(sbi, !cp_i);

	this_cp = HMFS_CHECKPOINT(args.src);
	/**
	 * 分别获取前一个和下一个检查点的地址，并用指针指向她们
	 */
	next_cp = ADDR(sbi, le64_to_cpu(this_cp->next_cp_addr));
	prev_cp = ADDR(sbi, le64_to_cpu(this_cp->prev_cp_addr));

	/**
	 *将前后检查点的地址信息放入目标地址中
	 */
	hmfs_memcpy_atomic(&next_cp->prev_cp_addr, &args.dest_addr, 8);
	hmfs_memcpy_atomic(&prev_cp->next_cp_addr, &args.dest_addr, 8);
	cp_i->cp = HMFS_CHECKPOINT(args.dest);
	
	/**
	 *遍历要在两个孤立块中写的地址，同时对孤立地址也写到目的地址中
	 */
	for (i = 0; i < NUM_ORPHAN_BLOCKS; i++) {
		orphan_addr = le64_to_cpu(this_cp->orphan_addrs[i]);
		if (orphan_addr == NULL_ADDR)
			break;
		orphan = ADDR(sbi, orphan_addr);
		hmfs_memcpy_atomic(orphan, &args.dest_addr, 8);
	}

	update_dest_summary(src_sum, args.dest_sum);
}

/*
 *cc14 garbage_collect:进行垃圾收集
 *@sbi:指向超级块信息的指针实例
 *@src_segno：源段号类型
 *@segno:段号的类型
 */
/**
 * garbage_collect:进行垃圾收集
 * @param[in]    sbi     指向超级块信息的指针实例
 * @param[in]    src_segno  源段号类型
 * @param[in]    segno    段号的类型
 * @ref          gc.h,node.h,segment.h,xattr.h,hmfs.h，hmfs_fs.h
 * @see
 * @note
 */
static void garbage_collect(struct hmfs_sb_info *sbi, seg_t segno)
{
	int off = 0;
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	bool is_current, none_valid;
	nid_t nid;
	/**
	 *定义summary的块的实例
	 */
	struct hmfs_summary_block *sum_blk;
	struct hmfs_summary *sum;

	/**
	 * 判断当前段中是否有有效块
	 */
	none_valid = !get_seg_entry(sbi, segno)->valid_blocks;

	if (none_valid)
		goto recycle;

	/**
	 * 返回summary入口地址
	 */
	sum_blk = get_summary_block(sbi, segno);
	sum = sum_blk->entries;

	//#ERROR: inconsistent of segno->valid_blocks
	for (off = 0; off < HMFS_PAGE_PER_SEG; ++off, sum++) {
		is_current  = get_summary_start_version(sum) == cm_i->new_version;

		/*
		 * We ignore two kinds of blocks:
		 * 	- invalid blocks in older version
		 * 	- newest blocks in newest version(checkpoint is not written)
		 */
		/**
		 * 如果是旧版本的无效块，或者最新版本中最新的块(即检查点还未完成则不清理)
		 */
		if (!get_summary_valid_bit(sum) && !is_current)
			continue;

		if (is_current) {
			nid = get_summary_nid(sum);
			if (IS_ERR(get_node(sbi, nid))){
				continue;
			}
		}

		/**
		 *根据summaryr入口地址的信息获取summary表的类型，并且在清理段之前作相应的转移工作，比如迁移有效的块和数据
		 */
		hmfs_bug_on(sbi, get_summary_valid_bit(sum) && is_current);
		switch (get_summary_type(sum)) {
		case SUM_TYPE_DATA:
			move_data_block(sbi, segno, off, sum);
			break;
		case SUM_TYPE_XDATA:
			move_xdata_block(sbi, segno, off, sum);
			break;
		case SUM_TYPE_INODE:
		case SUM_TYPE_DN:
			/**
			 *如果是不直接的块进行节点迁移处理
			 */
		case SUM_TYPE_IDN:
			move_node_block(sbi, segno, off, sum);
			break;
		case SUM_TYPE_NATN:
			/**
			 * 如果是NAT的数据块，也进行相应移动NAT块的处理
			 */
		case SUM_TYPE_NATD:
			hmfs_bug_on(sbi, is_current);
			move_nat_block(sbi, segno, off, sum);
			continue;
			/**
			 *处理迁移孤立的块
			 */
		case SUM_TYPE_ORPHAN:
			hmfs_bug_on(sbi, is_current);
			move_orphan_block(sbi, segno, off, sum);
			continue;
			/**
			 * 处理进行检查点迁移的块
			 */
		case SUM_TYPE_CP:
			hmfs_bug_on(sbi, is_current);
			move_checkpoint_block(sbi, segno, off, sum);
			continue;
		default:
			hmfs_bug_on(sbi, 1);
			break;
		}
	}

recycle:
/**
 *回收无效的块
 */
	recycle_segment(sbi, segno, none_valid);
}
/*
 *cc15 hmfs_gc:
 *@sbi:指向超级块信息的指针实例
 *@gc_type:垃圾回收的类型
 */
/**
 * hmfs_gc: 垃圾收集
 * @param[in]    sbi     指向超级块信息的指针实例
 * @param[in]    gc_type:垃圾回收的类型
 * @return       返回写检查点标识
 * @ref          gc.h,node.h,segment.h,xattr.h,hmfs.h，hmfs_fs.h
 * @see
 * @note
 */
int hmfs_gc(struct hmfs_sb_info *sbi, int gc_type)
{
	int ret = -1;
	seg_t segno, start_segno = NULL_SEGNO;
	struct hmfs_checkpoint *hmfs_cp = CM_I(sbi)->last_cp_i->cp;
	bool do_cp = false;
	int total_segs = TOTAL_SEGS(sbi);
	int time_retry = 0;
	/**
	 * 定义最大的要尝试回收的段数
	 */
	int max_retry = (total_segs + MAX_SEG_SEARCH - 1) / MAX_SEG_SEARCH;

	hmfs_dbg("Enter GC\n");
	INC_GC_TRY(STAT_I(sbi));
	if (!(sbi->sb->s_flags & MS_ACTIVE))
		goto out;

	/**
	 *设置文件系统收集的类型
	 */
	if (hmfs_cp->state == HMFS_NONE)
		set_fs_state(hmfs_cp, HMFS_GC);

	/**
	 * 处理垃圾收集的类型是BG或者没有足够的空闲的段
	 */
	if (gc_type == BG_GC && has_not_enough_free_segs(sbi)) {
		gc_type = FG_GC;
	}

gc_more:
	hmfs_dbg("Before get victim:%ld %ld %ld\n", (unsigned long)total_valid_blocks(sbi),
			(unsigned long)CM_I(sbi)->alloc_block_count, 
			(unsigned long)CM_I(sbi)->valid_block_count);
	/**
	 * 获取段里面victim的块
	 */
	if (!get_victim(sbi, &segno, gc_type))
		goto out;
	ret = 0;

	hmfs_dbg("GC Victim:%d %d\n", (int)segno, get_valid_blocks(sbi, segno));
	INC_GC_REAL(STAT_I(sbi));

	/*
	 * If a segment does not contains any valid blocks, we do not 
	 * need to set it as PREFREE. And we could reuse it right now, which
	 * could improve GC efficiency
	 */
	/**
	 *根据段的入口块获取有效的块数，垃圾收集时的日志域加1，已经收集的段数也加1
	 */
	if (get_seg_entry(sbi, segno)->valid_blocks) {
		hmfs_memcpy_atomic(sbi->gc_logs, &segno, 4);		
		sbi->gc_logs++;
		sbi->nr_gc_segs++;
		hmfs_memcpy_atomic(&hmfs_cp->nr_gc_segs, &sbi->nr_gc_segs, 4);
	}

	/**
	 *统计当前超级块实例下每段中要进行垃圾收集的块数，并且收集它们
	 */
	COUNT_GC_BLOCKS(STAT_I(sbi), HMFS_PAGE_PER_SEG - 
			get_valid_blocks(sbi, segno));

	hmfs_bug_on(sbi, total_valid_blocks(sbi) != CM_I(sbi)->valid_block_count);
	garbage_collect(sbi, segno);

	hmfs_dbg("GC:%ld %ld %ld\n", (unsigned long)total_valid_blocks(sbi),
			(unsigned long)CM_I(sbi)->alloc_block_count, 
			(unsigned long)CM_I(sbi)->valid_block_count);
	hmfs_bug_on(sbi, total_valid_blocks(sbi) != CM_I(sbi)->valid_block_count);

	if (start_segno == NULL_SEGNO)
		start_segno = segno;

	/* If space is limited, we might need to scan the whole NVM */
	/**
	 * 如果空间有限，则重新扫描整个NVM
	 */
	if (need_deep_scan(sbi)) {
		do_cp = true;
		time_retry++;
		if (time_retry < max_retry)
			goto gc_more;
		goto out;
	}

	/* In FG_GC, we atmost scan sbi->nr_max_fg_segs segments */
	/**
	 *在FG类型的垃圾收集总，最多扫描当前环境下一定数量的段
	 */
	if (has_not_enough_free_segs(sbi) && need_more_scan(sbi, segno, start_segno))
		goto gc_more;

out:
    /**
     *处理victim的段，进行检查点信息的设置
     */
	if (do_cp) {
		ret= write_checkpoint(sbi, true);
		hmfs_bug_on(sbi, ret);
		hmfs_dbg("Write checkpoint done\n");
	}

	unlock_gc(sbi);
	hmfs_dbg("Exit GC:%ld %ld %ld\n", (unsigned long)total_valid_blocks(sbi),
			(unsigned long)CM_I(sbi)->alloc_block_count, 
			(unsigned long)CM_I(sbi)->valid_block_count);
	return ret;
}
/**
 * cc16 gc_thread_func:实时更新在超级块信息中垃圾回收进程的等待时间
 *@data：初始化当前超级块的信息
 *@return:成功，返回0
 */
/**
 * gc_thread_func:实时更新在超级块信息中垃圾回收进程的等待时间
 * @param[in]    data：初始化当前超级块的信息
 * @return       返回0
 * @ref          gc.h,node.h,segment.h,xattr.h,hmfs.h，hmfs_fs.h
 * @see
 * @note
 */
static int gc_thread_func(void *data)
{
	struct hmfs_sb_info *sbi = data;
	wait_queue_head_t *wq = &(sbi->gc_thread->gc_wait_queue_head);
	long wait_ms = 0;
	printk(KERN_INFO "start gc thread\n");
	wait_ms = sbi->gc_thread_min_sleep_time;

	do {
		if (try_to_freeze())
			continue;
		else
			/**
			 *如果超时或者条件满足时，就启动垃圾回收的进程
			 */
			wait_event_interruptible_timeout(*wq, kthread_should_stop(),
					msecs_to_jiffies(wait_ms));

		if (kthread_should_stop())
			break;

		/**
		 * 如果当前超级块记录中空闲写的时间与记录不符合，则更新相应的垃圾回收最大睡眠时间
		 */
		if (sbi->sb->s_writers.frozen >= SB_FREEZE_WRITE) {
			wait_ms = sbi->gc_thread_max_sleep_time;
			continue;
		}

		if (!trylock_gc(sbi))
			continue;
		/**
		 * 如果当前超级块记录中已经有了足够多无效的块，就可以释放等待时间，准备进行垃圾回收了
		 */
		if (has_enough_invalid_blocks(sbi))
			wait_ms = decrease_sleep_time(sbi, wait_ms);
		else
			wait_ms = increase_sleep_time(sbi, wait_ms);

		if (hmfs_gc(sbi, BG_GC)) {
//			if (wait_ms == sbi->gc_thread_max_sleep_time)
//				wait_ms = GC_THREAD_NOGC_SLEEP_TIME;
		}
	} while (!kthread_should_stop());
	return 0;
}
/**
 * cc17 start_gc_thread: 开始处理垃圾回收进程时，先判断当前进程是否出错
 * @sbi:指向超级块信息的指针实例
 * @return:如果出错，返回错误标识
 */
/**
 * start_gc_thread:开始处理垃圾回收进程时，先判断当前进程是否出错
 * @param[in]    sbi  指向超级块信息的指针实例
 * @return       如果出错，返回错误标识
 * @ref          gc.h,node.h,segment.h,xattr.h,hmfs.h，hmfs_fs.h
 * @see
 * @note
 */
int start_gc_thread(struct hmfs_sb_info *sbi)
{
	struct hmfs_gc_kthread *gc_thread = NULL;
	int err = 0;
	unsigned long start_addr, end_addr;

	start_addr = sbi->phys_addr;
	end_addr = sbi->phys_addr + sbi->initsize;
	sbi->last_victim[GC_CB] = 0;
	sbi->last_victim[GC_GREEDY] = 0;

	gc_thread = kmalloc(sizeof(struct hmfs_gc_kthread), GFP_KERNEL);
	if (!gc_thread) {
		err = -ENOMEM;
		goto out;
	}

	/**
	 * 初始化垃圾回收进程的等待队列队头，同时初始化垃圾回收进程的回收任务
	 */
	sbi->gc_thread = gc_thread;
	init_waitqueue_head(&(sbi->gc_thread->gc_wait_queue_head));
	sbi->gc_thread->hmfs_gc_task = kthread_run(gc_thread_func, sbi,
										"hmfs_gc-%lu:->%lu",
										start_addr, end_addr);
	/**
	 *如果出错，释放当前进程
	 */
	if (IS_ERR(gc_thread->hmfs_gc_task)) {
		err = PTR_ERR(gc_thread->hmfs_gc_task);
		kfree(gc_thread);
		sbi->gc_thread = NULL;
	}
out:
	return err;
}
/**
 * cc18 stop_gc_thread: 根据垃圾回收进程的任务信息，停止当前进程
 * @sbi:指向超级块信息的指针实例
 */
/**
 * stop_gc_thread: 根据垃圾回收进程的任务信息，停止当前进程
 * @param[in]    sbi  指向超级块信息的指针实例
 * @ref          gc.h,node.h,segment.h,xattr.h,hmfs.h，hmfs_fs.h
 * @see
 * @note
 */
void stop_gc_thread(struct hmfs_sb_info *sbi)
{
	struct hmfs_gc_kthread *gc_thread = sbi->gc_thread;
	if (!gc_thread)
		return;
	kthread_stop(gc_thread->hmfs_gc_task);
	kfree(gc_thread);
	sbi->gc_thread = NULL;
}

/**
 *cc19 init_gc_logs:初始化垃圾回收的日志信息
 * @sbi:指向超级块信息的指针实例
 * @return:返回是否能获取一个新的空闲段标识
 */
int init_gc_logs(struct hmfs_sb_info *sbi)
{
	seg_t segno;
	int ret;
	block_t addr;
	struct hmfs_checkpoint *hmfs_cp = CM_I(sbi)->last_cp_i->cp;
	/**
	 * 判断是否能从超级块信息中获取一个新的空闲段，如果成功了该段用来记录垃圾回收的日志信息，
	 *
	 */
	ret = get_new_segment(sbi, &segno);
	if (!ret) {
		addr = __cal_page_addr(sbi, segno, 0);
		sbi->gc_logs = ADDR(sbi, addr);
		sbi->nr_gc_segs = 0;
		hmfs_cp->gc_logs = cpu_to_le32(segno);
		hmfs_cp->nr_gc_segs = 0;
	}

	return ret;
}

/* Must call move_to_next_checkpoint() before this function */
/**
 *cc20 reinit_gc_logs: 在最新的检查点中重新初始化垃圾回收的日志记录
 * @sbi:指向超级块信息的指针实例
 *
 */
/**
 * reinit_gc_logs: 在最新的检查点中重新初始化垃圾回收的日志记录
 * @param[in]    sbi  指向超级块信息的指针实例
 * @ref          gc.h,node.h,segment.h,xattr.h,hmfs.h，hmfs_fs.h
 * @see
 * @note
 */
void reinit_gc_logs(struct hmfs_sb_info *sbi)
{
	seg_t old_segno;
	block_t old_addr;
	struct free_segmap_info *free_i = FREE_I(sbi);
	struct hmfs_checkpoint *hmfs_cp = CM_I(sbi)->last_cp_i->cp;

	old_addr = L_ADDR(sbi, sbi->gc_logs);
	old_segno = GET_SEGNO(sbi, old_addr);

	/* 
	 * We try to get a different segments for gc logs in order to protect
	 * NVM area. And we have make a checkpoint now. We need to set gc_logs
	 * and nr_gc_segs for new 'last checkpoint'
	 */
	/**
	 * 如果不能从NVM的Main Area中获取新的空闲段，则清除旧的段号名，同时对新的空闲段加1，否则将垃圾回收
	 * 的旧的日志信息和段号更新最新的检查点信息
	 */
	if (!init_gc_logs(sbi)) {
		lock_write_segmap(free_i);
		if (test_and_clear_bit(old_segno, free_i->free_segmap))
			free_i->free_segments++;
		unlock_write_segmap(free_i);
	} else {
		hmfs_cp->gc_logs = cpu_to_le32(old_segno);
		hmfs_cp->nr_gc_segs = 0;
	}
}

/**
 *cc20 init_gc_stat:强垃圾回收的回收信息清零
 *@sbi:指向超级块信息的指针实例
 */
/**
 * init_gc_stat:强垃圾回收的回收信息清零
 * @param[in]    sbi  指向超级块信息的指针实例
 * @ref          gc.h,node.h,segment.h,xattr.h,hmfs.h，hmfs_fs.h
 * @see
 * @note
 */
void init_gc_stat(struct hmfs_sb_info *sbi) {
	struct hmfs_stat_info *si = STAT_I(sbi);
	int i;

	si->nr_gc_try = 0;
	si->nr_gc_real = 0;
	si->nr_gc_blocks = 0;
	for (i = 0; i < SIZE_GC_RANGE; i++) {
		si->nr_gc_blocks_range[i] = 0;
	}
}

