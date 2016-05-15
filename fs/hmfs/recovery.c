/*
 * fs/hmfs/recovery.c
 *
 * Copyright (c) 2015 SJTU RadLab
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "hmfs.h"
#include "hmfs_fs.h"
#include "gc.h"
#include "segment.h"
#include "node.h"
#include "xattr.h"
/**
 *cc1 recovery_data_block:依次恢复数据块的相关数据
 *@sbi:指向超级块信息的指针实例
 *@src_segno:源段号
 *@src_off:偏移量
 *@src_sum:指向父节点的summary表的指针
 */
static void recovery_data_block(struct hmfs_sb_info *sbi, seg_t src_segno,
				int src_off, struct hmfs_summary *src_sum)
{
	struct gc_move_arg args;
	struct hmfs_node *last = NULL, *this = NULL;
	struct hmfs_summary *par_sum;
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	bool modify_vb = false;
	block_t addr_in_par;
	int par_type;

	prepare_move_argument(&args, sbi, src_segno, src_off, src_sum,
			TYPE_DATA);

	while (1) {
		/**
		 * 根据参数集里的检查点信息和node id得到其summary表，如果该node已经被删除了，则停止；
		 * 如果是空的节点，则获取上一个检查点中的信息
		 */
		this = __get_node(sbi, args.cp_i, args.nid);

		par_sum = get_summary_by_addr(sbi, L_ADDR(sbi, this));

		if (IS_ERR(this)) {
			/* the node(args.nid) has been deleted */
			break;
		}

		if (this == last)
			goto next;
        /**
         *获取该块的类型，如果是inode块，则获取inode块的偏移量，并赋值给块号，否则把direct node赋值给块号
         */
		par_type = get_summary_type(par_sum);
		if (par_type == SUM_TYPE_INODE) {
			addr_in_par = le64_to_cpu(this->i.i_addr[args.ofs_in_node]);
		} else {
			addr_in_par = le64_to_cpu(this->dn.addr[args.ofs_in_node]);
		}

		/*
		 * In recovery, the address stored in parent node would be
		 * arg.src_addr or an invalid address. Because GC might terminate
		 * in the loop change this address.
		 * Condition addr_in_par != args.src_addr is not sufficient
		 * to terminate recovery. For example, we delete a node in a
		 * checkpoint and reuse it later. And address in reused node
		 * is not equal to args.src_addr but we could not modify it.
		 * Luckly, the child block in that node is valid and we could
		 * judge this case by the value of address.
		 */
		/**
		 * 如果地址等于了参数集中父节点的node地址并且还是有效地址，则停止恢复
		 */
		if (addr_in_par != args.src_addr && is_valid_address(sbi, addr_in_par))
			break;
		
		if (addr_in_par != args.src_addr) {
			/* Recover address in parent node */
			/**
			 *恢复父节点中inode或者direct node的父节点地址
			 */
			if (par_type == SUM_TYPE_INODE) {
				hmfs_memcpy_atomic(&this->i.i_addr[args.ofs_in_node],
						&args.src_addr, 8);
			} else {
				hmfs_memcpy_atomic(&this->dn.addr[args.ofs_in_node],
						&args.src_addr, 8);
			}
            /**
             *清除目的summary块的有效位地址
             */
			if (!modify_vb) {
				args.dest_sum = get_summary_by_addr(sbi, addr_in_par);
				clear_summary_valid_bit(args.dest_sum);
				modify_vb = true;
			}
		}

		last = this;
next:
		if (args.cp_i == cm_i->last_cp_i)
			break;
		args.cp_i = get_next_checkpoint_info(sbi, args.cp_i);
	}
}
/**
 *cc2 recovery_xdata_block:恢复额外数据块的数据信息
 *@sbi:指向超级块信息的指针实例
 *@src_segno:源段号
 *@src_off:偏移量
 *@src_sum:指向父节点的summary表的指针
 */
static void recovery_xdata_block(struct hmfs_sb_info *sbi, seg_t src_segno,
				int src_off, struct hmfs_summary *src_sum)
{
	struct gc_move_arg arg;
	struct hmfs_node *last = NULL, *this = NULL;
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	block_t addr_in_par;
	bool modify_vb = false;
	int x_tag;

	prepare_move_argument(&arg, sbi, src_segno, src_off, src_sum,
			TYPE_DATA);

	while (1) {
		/**
		  * 根据参数集里的检查点信息和node id得到其summary表，如果该node已经被删除了，则停止；
		  * 如果是空的节点，则获取上一个检查点中的信息
		  */
		this = __get_node(sbi, arg.cp_i, arg.nid);

		if (IS_ERR(this))
			break;

		if (this == last)
			goto next;
        /**
         *获取额外数据块的地址
         */
		x_tag = le64_to_cpu(XATTR_HDR(arg.src)->h_magic);
		addr_in_par = XBLOCK_ADDR(this, x_tag);
		/**
	      * 如果地址等于了参数集中父节点的node地址并且还是有效地址，则停止恢复
		  */
		if (addr_in_par != arg.src_addr && is_valid_address(sbi, addr_in_par)) {
			break;
		}
		
		if (addr_in_par != arg.src_addr) {
			hmfs_memcpy_atomic(JUMP(this, x_tag), &arg.src_addr, 8);
			 /**
			   *清除目的summary块的有效位地址
			   */
			if (!modify_vb) {
				arg.dest_sum = get_summary_by_addr(sbi, addr_in_par);
				clear_summary_valid_bit(arg.dest_sum);
				modify_vb = true;
			}
		}

		last = this;

next:
		if (arg.cp_i == cm_i->last_cp_i)
			break;
		arg.cp_i = get_next_checkpoint_info(sbi, arg.cp_i);
	}
}
/**
 *cc3 recovery_node_block:恢复node块的数据信息
 *@sbi:指向超级块信息的指针实例
 *@src_segno:源段号
 *@src_off:偏移量
 *@src_sum:指向父节点的summary表的指针
 */
static void recovery_node_block(struct hmfs_sb_info *sbi, seg_t src_segno,
			    unsigned int src_off, struct hmfs_summary *src_sum)
{
	struct hmfs_nat_block *last = NULL, *this = NULL;
	struct gc_move_arg args;
	block_t addr_in_par;
	bool modify_vb = false;

	prepare_move_argument(&args, sbi, src_segno, src_off, src_sum, TYPE_NODE);

	while (1) {
		/**
		  * 根据参数集里的检查点版本信息和node id得到其NAT entry表，
		  * 如果该node已经被删除了，则停止；
		  * 如果是空的节点，则获取上一个检查点中的信息
	      */
		this = get_nat_entry_block(sbi, args.cp_i->version, args.nid);
		if (IS_ERR(this))
			break;

		if (this == last)
			goto next;

		addr_in_par = le64_to_cpu(this->entries[args.ofs_in_node].block_addr);
		/* Src node has been COW or removed */
		/**
		 * 如果源节点是COW的或者被移除了
		 */
		if (addr_in_par != args.src_addr && is_valid_address(sbi, addr_in_par)) {
			break;
		}

		if (addr_in_par != args.src_addr) {
			hmfs_memcpy_atomic(&this->entries[args.ofs_in_node].block_addr,
					&args.src_addr, 8);
			if (!modify_vb) {
				 /**
				   *清除目的summary块的有效位地址
				   */
				args.dest_sum = get_summary_by_addr(sbi, addr_in_par);
				clear_summary_valid_bit(args.dest_sum);
				modify_vb = true;
			}
		}

		last = this;

next:
		if (args.cp_i == CM_I(sbi)->last_cp_i)
			break;
		args.cp_i = get_next_checkpoint_info(sbi, args.cp_i);
	}
}
/**
 *cc4 recovery_nat_block:恢复NAT块的数据信息
 *@sbi:指向超级块信息的指针实例
 *@src_segno:源段号
 *@src_off:偏移量
 *@src_sum:指向父节点的summary表的指针
 */
static void recovery_nat_block(struct hmfs_sb_info *sbi, seg_t src_segno, int src_off,
			   struct hmfs_summary *src_sum)
{
	void *last = NULL, *this = NULL;
	struct hmfs_checkpoint *hmfs_cp = NULL;
	struct hmfs_nat_node *nat_node = NULL;
	struct gc_move_arg args;
	bool modify_vb = false;
	nid_t par_nid;
	block_t addr_in_par;

	prepare_move_argument(&args, sbi, src_segno, src_off, src_sum, TYPE_NODE);

	while (1) {
		/**
		  *根据参数集中的node id信息判断其是否是NAT表的根节点，如果是，记录该检查点信息
		  */
		if (IS_NAT_ROOT(args.nid))
			this = args.cp_i->cp;
		else {
			/**
			 *否则根据NAT树的高和偏移量求得该node块的父节点的node id号，并且根据父节点的检查点和node ID
			 *号得到该node block号码
			 */
			par_nid = MAKE_NAT_NODE_NID(GET_NAT_NODE_HEIGHT(args.nid) - 1, 
							GET_NAT_NODE_OFS(args.nid)); 
			this = get_nat_node(sbi, args.cp_i->version, par_nid);
		}

		hmfs_bug_on(sbi, !this);
		if (this == last)
			goto next;
        /**
         *如果是NAT树的根节点，则得到其nat地址，否则根据偏移量得到地址
         */
		if (IS_NAT_ROOT(args.nid)) {
			hmfs_cp = HMFS_CHECKPOINT(this);
			addr_in_par = le64_to_cpu(hmfs_cp->nat_addr);
		} else {
			nat_node = HMFS_NAT_NODE(this);
			addr_in_par = le64_to_cpu(nat_node->addr[args.ofs_in_node]);
		}
		/**
	      * 如果地址等于了参数集中父节点的node地址并且还是有效地址，则停止恢复
		  */
		if (addr_in_par != args.src_addr && is_valid_address(sbi, addr_in_par)) {
			break;
		}

		if (addr_in_par != args.src_addr) {
			if (IS_NAT_ROOT(args.nid)) {
				hmfs_memcpy_atomic(&hmfs_cp->nat_addr, &args.src_addr, 8);
			} else {
				hmfs_memcpy_atomic(&nat_node->addr[args.ofs_in_node], 
						&args.src_addr, 8);
			}

			if (!modify_vb) {
				/**
				  *清除目的summary块的有效位地址
				  */
				args.dest_sum = get_summary_by_addr(sbi, addr_in_par);
				clear_summary_valid_bit(args.dest_sum);
				modify_vb = true;
			}
		}

		last = this;

next:
		if (args.cp_i == CM_I(sbi)->last_cp_i)
			break;
		args.cp_i = get_next_checkpoint_info(sbi, args.cp_i);
	}
}
/**
 *cc5 recovery_orphan_block:恢复孤立块的地址
 *@sbi:指向超级块信息的指针实例
 *@src_segno:源段号
 *@src_off:偏移量
 *@src_sum:指向父节点的summary表的指针
 */
static void recovery_orphan_block(struct hmfs_sb_info *sbi, seg_t src_segno, 
				int src_off, struct hmfs_summary *src_sum)
{
	struct gc_move_arg args;
	struct hmfs_checkpoint *hmfs_cp;
	block_t cp_addr, orphan_addr;

	prepare_move_argument(&args, sbi, src_segno, src_off, src_sum,
			TYPE_NODE);
	/**
	 *获取源地址、检查点地址、孤立点的地址
	 */
	cp_addr = le64_to_cpu(*((__le64 *)args.src));
	hmfs_cp = ADDR(sbi, cp_addr);
	orphan_addr = le64_to_cpu(hmfs_cp->orphan_addrs[get_summary_offset(src_sum)]);
    /**
     *如果孤立节点的地址不等于父节点的node地址，
     *重新记录孤立节点的偏移量，同时得到其summary表后清除summary块的有效位地址
     */
	if (orphan_addr != args.src_addr) {
		hmfs_cp->orphan_addrs[get_summary_offset(src_sum)] = 
				cpu_to_le64(args.src_addr);
		args.dest_sum = get_summary_by_addr(sbi, orphan_addr);
		clear_summary_valid_bit(args.dest_sum);
	}
}
/**
 *cc6 recovery_checkpoint_block:根据检查点的信息恢复CP块
 *@sbi:指向超级块信息的指针实例
 *@src_segno:源段号
 *@src_off:偏移量
 *@src_sum:指向父节点的summary表的指针
 */
static void recovery_checkpoint_block(struct hmfs_sb_info *sbi, seg_t src_segno,
				int src_off, struct hmfs_summary *src_sum)
{
	struct hmfs_checkpoint *prev_cp, *next_cp, *this_cp;
	block_t addr_in_other, cp_addr;
	struct hmfs_summary *dest_sum;
	int i;
	block_t orphan_addr;
	__le64 *orphan;

	/*
	 * We could not use prepare_move_argument here. Because it might
	 * break the checkpoint list due to checkpoint list is inconsistent
	 * in NVM
	 */
	/**
	 *这里我们不用prepare_move_argument函数，因为可能会打破检查点链表，因为检查点链表在NVM中是不稳定的
	 *获取检查点地址和下一个前一个检查点的地址
	 */
	cp_addr = __cal_page_addr(sbi, src_segno, src_off);
	this_cp = HMFS_CHECKPOINT(cp_addr);
	next_cp = ADDR(sbi, le64_to_cpu(this_cp->next_cp_addr));
	prev_cp = ADDR(sbi, le64_to_cpu(this_cp->prev_cp_addr));

	addr_in_other = le64_to_cpu(next_cp->prev_cp_addr);
	/**
	 *如果链表中下一个检查点的地址的前一个不等于当前检查点的地址，则调节对应关系
	 *另外根据地址获得summary表，同时清除有效位
	 */
	if (addr_in_other != cp_addr) {
		next_cp->prev_cp_addr = cpu_to_le64(cp_addr);
		prev_cp->next_cp_addr = cpu_to_le64(cp_addr);
		dest_sum = get_summary_by_addr(sbi, addr_in_other);
		clear_summary_valid_bit(dest_sum);
	}
    /**
     *依次检查所有孤立的块，如果有孤立的块，记录
     */
	for (i = 0; i < NUM_ORPHAN_BLOCKS; i++) {
		orphan_addr = le64_to_cpu(this_cp->orphan_addrs[i]);
		if (orphan_addr == NULL_ADDR)
			break;
		orphan = ADDR(sbi, orphan_addr);
		hmfs_memcpy_atomic(orphan, &cp_addr, 8);
	}
}
/**
 *cc7 recovery_gc_segment:根据段号summary表的类型做相应的恢复操作
 *@sbi:指向超级块信息的指针实例
 *@segno:要回收垃圾的段号
 */
static void recovery_gc_segment(struct hmfs_sb_info *sbi, seg_t segno)
{
	int off = 0;
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	bool is_current;
	struct hmfs_summary *sum;
	block_t seg_addr;
    /**
     *记录段地址，并用词找到summary表
     */
	seg_addr = __cal_page_addr(sbi, segno, 0);
	sum = get_summary_by_addr(sbi, seg_addr);

	for (off = 0; off < HMFS_PAGE_PER_SEG; ++off, sum++) {
		/**
		 *判断summary表的版本信息和检查点管理器的最新版本信息是否吻合
		 *如果是不是吻合的或者summary表中没有有效位
		 */
		is_current = get_summary_start_version(sum)	== cm_i->new_version;

		if ((!get_summary_valid_bit(sum) && !is_current) || is_current)
			continue;
        /**
         *根据summary表判断其类型
         */
		switch (get_summary_type(sum)) {
		case SUM_TYPE_DATA:
			recovery_data_block(sbi, segno, off, sum);
			break;
		case SUM_TYPE_XDATA:
			recovery_xdata_block(sbi, segno, off, sum);
			break;
		case SUM_TYPE_INODE:
		case SUM_TYPE_DN:
		case SUM_TYPE_IDN:
			/**
			 *如果是indirect块，则根据节点块的恢复方式进行
			 */
			recovery_node_block(sbi, segno, off, sum);
			break;
		case SUM_TYPE_NATN:
		case SUM_TYPE_NATD:
			/**
			  *如果是NAT数据块，则根据NAT块的恢复方式进行
		       */
			recovery_nat_block(sbi, segno, off, sum);
			break;
		case SUM_TYPE_ORPHAN:
			recovery_orphan_block(sbi, segno, off, sum);
			break;
		case SUM_TYPE_CP:
			recovery_checkpoint_block(sbi, segno, off, sum);
			break;
		default:
			hmfs_bug_on(sbi, 1);
		}
	}
}

/* 
 * In GC process, we have mark the valid bit in summary. It's hard
 * to redo GC process. But we have an idea which block is mark as
 * valid and we need to reset the valid its of them.
 */
/**
 *cc8 recovery_gc_crash:根据检查点记录依次进行垃圾回收操作
 *@sbi:指向超级块信息的指针实例
 *@hmfs_cp:指向当前检查点的实例
 */
void recovery_gc_crash(struct hmfs_sb_info *sbi, struct hmfs_checkpoint *hmfs_cp)
{
	void *new_gc_logs;
	int nr_gc_segs;
	block_t log_addr;
	int i;
	seg_t segno;
    /**
     *记录垃圾回收的日志区域，得到垃圾回收的日志区域所在的地址
     */
	new_gc_logs = sbi->gc_logs;
	nr_gc_segs = le32_to_cpu(hmfs_cp->nr_gc_segs);
	log_addr = __cal_page_addr(sbi, le32_to_cpu(hmfs_cp->gc_logs), 0);
	sbi->gc_logs = ADDR(sbi, log_addr);
	/**
	 *依次遍历所有的段，根据每一段做相应的垃圾回收操作
	 */
	for (i = 0; i < nr_gc_segs; i++, sbi->gc_logs++) {
		segno = le32_to_cpu(*sbi->gc_logs);
		recovery_gc_segment(sbi, segno);
	}

	sbi->gc_logs = new_gc_logs;
}
