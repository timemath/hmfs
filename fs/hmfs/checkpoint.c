#include "hmfs.h"
#include "hmfs_fs.h"
#include "segment.h"
#include <linux/crc16.h>
#include <linux/pagevec.h>

static struct kmem_cache *orphan_entry_slab;

static struct kmem_cache *cp_info_entry_slab;

/**
 *cc1 modify_checkpoint_version:当发生修改时，修改NAT树种各类块的子节点的版本信息
 *@sbi:指向当前版本下超级块信息的实例
 *@block:块号
 *@prev_ver:以前的版本号
 *@new_ver:新的版本号
 */
static void modify_checkpoint_version(struct hmfs_sb_info *sbi, void *block,
				ver_t prev_ver, ver_t new_ver)
{
	struct hmfs_summary *summary;
	ver_t cur_ver;
	block_t block_addr;
	void *child_block;
	int i;

	/**
	 *根据块号获取块地址，进而获取块的信息表没，从而获得该块的当前版本
	 */
	block_addr = L_ADDR(sbi, block);
	summary = get_summary_by_addr(sbi, block_addr);
	cur_ver = get_summary_start_version(summary);

	/* This block and its children could be reach from previous checkpoint */
	if (cur_ver <= prev_ver) {
		return;
	}

	set_summary_start_version(summary, new_ver);

	switch (get_summary_type(summary)) {
	/**
	 *用新的版本信息修改当前nat node block的孩子节点的版本号
	 */
	case SUM_TYPE_NATN: {
		__le64 *child = HMFS_NAT_NODE(block)->addr;

		/* Modify version of nat node */
		for (i = 0; i < NAT_ADDR_PER_NODE; i++, child++) {
			if (!*child)
				continue;
			child_block = ADDR(sbi, le64_to_cpu(*child));
			modify_checkpoint_version(sbi, child_block, prev_ver, new_ver);
		}
		break;
	}
	    /**
		 *如果是NAT树的数据块，且entry结点发生了改变，则相应地修改各类结点的的子节点的版本号为最新版本号
		 */
	case SUM_TYPE_NATD: {
		struct hmfs_nat_entry *entry;

		/* Modify version of all kinds of nodes */
		entry = HMFS_NAT_BLOCK(block)->entries;
		for (i = 0; i < NAT_ENTRY_PER_BLOCK; i++, entry++) {
			if (!entry->ino)
				continue;
			child_block = ADDR(sbi, le64_to_cpu(entry->block_addr));
			modify_checkpoint_version(sbi, child_block, prev_ver, new_ver);
		}
		break;
	}

	/**
	 * 如果是inode块，修改inode块里面扩展块的子节点块的版本信息和数据块的版本信息
	 */
	case SUM_TYPE_INODE: {
		__le64 *child;
		struct hmfs_inode *inode_block;
		block_t xaddr;

		inode_block = HMFS_INODE(block);

		/* Modify version of extended blocks */
		for_each_xblock(inode_block, xaddr, i) {
			if (!xaddr)
				continue;
			child_block = ADDR(sbi, xaddr);
			modify_checkpoint_version(sbi, child_block, prev_ver, new_ver);
		}

		/* Modify version of data blocks */
		child = inode_block->i_addr;
		for (i = 0; i < NORMAL_ADDRS_PER_INODE; i++, child++) {
			if (!*child)
				continue;
			child_block = ADDR(sbi, le64_to_cpu(*child));
			modify_checkpoint_version(sbi, child_block, prev_ver, new_ver);
		}
		break;
	}

	/**
	 * 如果是direct块，则修改指向数据块的孩子节点的版本号
	 */
	case SUM_TYPE_DN: {
		__le64 *child = DIRECT_NODE(block)->addr;

		/* Modify version of data blocks of direct node */
		for (i = 0; i < ADDRS_PER_BLOCK; i++, child++) {
			if (!*child)
				continue;
			child_block = ADDR(sbi, le64_to_cpu(*child));
			modify_checkpoint_version(sbi, child_block, prev_ver, new_ver);
		}
		break;
	}

	/**
	 *如果是checkpoint块，则并且不是孤立节点，则修改检查点的版本号
	 *如果是孤立节点，记录当前检查点下所有的孤立节点，相应地修改版本信息
	 */
	case SUM_TYPE_CP: {
		struct hmfs_checkpoint *cur_cp;

		/* modify version of orphan blocks */
		cur_cp = HMFS_CHECKPOINT(block);
		for (i = 0; i < NUM_ORPHAN_BLOCKS; i++) {
			if (!cur_cp->orphan_addrs[i])
				break;
			child_block = ADDR(sbi, le64_to_cpu(cur_cp->orphan_addrs[i]));
			modify_checkpoint_version(sbi, child_block, prev_ver, new_ver);
		}

		child_block = ADDR(sbi, le64_to_cpu(cur_cp->nat_addr));
		modify_checkpoint_version(sbi, child_block, prev_ver, new_ver);
		break;
	}

	case SUM_TYPE_ORPHAN:
	case SUM_TYPE_DATA:
	case SUM_TYPE_IDN:
	case SUM_TYPE_XDATA:
		break;

	default:
		hmfs_bug_on(sbi, 1);
		break;
	}
}

//TODO: What if crash in this process
/**
 *cc2 recycle_version_number:回收当前的版本号
 *@sbi:指向当前版本下超级块信息的实例
 */
void recycle_version_number(struct hmfs_sb_info *sbi)
{
	struct hmfs_checkpoint *cur_cp, *last_cp;
	ver_t version = HMFS_DEF_CP_VER, prev_ver;

	last_cp = CM_I(sbi)->last_cp_i->cp;
	cur_cp = last_cp;
	prev_ver = HMFS_DEF_DEAD_VER;
	
	/*
	 * We first calculate how many checkpoint there are
	 */
	/**
	 *简单统计下已有的checkpoint的数目
	 */
	do {
		cur_cp = ADDR(sbi, le64_to_cpu(cur_cp->next_cp_addr));
		version++;
	} while(cur_cp != last_cp);

	/* We have increase additional 1 to version */
	version--;

	/*
	 * We modify checkpoint version from newest
	 * checkpoint to oldest checkpoint. It's ok because we cannot
	 * reach newer block from older checkpoint block.
	 */
	/**
	 * 修改版本号从最新的检查点到最旧的检查点
	 */
	cur_cp = CM_I(sbi)->last_cp_i->cp;
	while (version >= HMFS_DEF_CP_VER) {
		last_cp = ADDR(sbi, le64_to_cpu(cur_cp->prev_cp_addr));
		prev_ver = le32_to_cpu(last_cp->checkpoint_ver);
		modify_checkpoint_version(sbi, cur_cp, prev_ver, version);
		version--;
		cur_cp = last_cp;
	}
}
/**
 *cc3 next_checkpoint_ver:得到下一个版本号
 */
static ver_t next_checkpoint_ver(ver_t version)
{
	return version + 1;
}
/**
 *cc4 init_orphan_manager:初始化管理孤立点的实例
 *@cm_i:初始化检查点管理器的实例
 */
static void init_orphan_manager(struct hmfs_cm_info *cm_i)
{
	/* init orphan manager */
	mutex_init(&cm_i->orphan_inode_mutex);
	INIT_LIST_HEAD(&cm_i->orphan_inode_list);
	cm_i->n_orphans = 0;
}
/**
 *cc5 add_orphan_inode:增加孤立节点的inode到链表队尾
 *@sbi:指向当前版本下超级块信息的实例
 *@ino:节点的inode号
 */
void add_orphan_inode(struct hmfs_sb_info *sbi, nid_t ino)
{
	struct list_head *head, *this;
	struct orphan_inode_entry *new = NULL, *orphan = NULL;
	struct hmfs_cm_info *cm_i = CM_I(sbi);

	/**
	 *获取检查点管理器下孤立节点的链表，判断给定节点的inode和孤立节点里边中的节点号是否相同
	 */
	lock_orphan_inodes(cm_i);
	head = &cm_i->orphan_inode_list;
	list_for_each(this, head) {
		orphan = list_entry(this, struct orphan_inode_entry, list);
		if (orphan->ino == ino)
			goto out;
		if (orphan->ino > ino)
			break;
		orphan = NULL;
	}
	/**
	 *如果不同，增加新的孤立节点到孤立节点的队尾。并且对孤立节点数加1
	 */
retry:
	new = kmem_cache_alloc(orphan_entry_slab, GFP_ATOMIC);
	if (!new) {
		cond_resched();
		goto retry;
	}
	new->ino = ino;

	if (orphan)
		list_add(&new->list, this->prev);
	else
		list_add_tail(&new->list, head);
	cm_i->n_orphans++;
out:	
	unlock_orphan_inodes(cm_i);
}
/**
 *cc6 remove_orphan_inode:删除不再需要的孤立节点的inode
 *@sbi:指向当前版本下超级块信息的实例
 *@ino:节点的inode号
 */
void remove_orphan_inode(struct hmfs_sb_info *sbi, nid_t ino)
{
	struct list_head *this, *next, *head;
	struct orphan_inode_entry *orphan;
	struct hmfs_cm_info *cm_i = CM_I(sbi);

	lock_orphan_inodes(cm_i);
	head = &cm_i->orphan_inode_list;
	/**
	 * 遍历当前孤立节点链表的inode号，如果等于要删除的节点的inode号，则释放该孤立点所占据的空间，同时孤立节点数减一
	 */
	list_for_each_safe(this, next, head) {
		orphan = list_entry(this, struct orphan_inode_entry, list);
		if (orphan->ino == ino) {
			list_del(&orphan->list);
			INIT_LIST_HEAD(&orphan->list);
			kmem_cache_free(orphan_entry_slab, orphan);
			cm_i->n_orphans--;
			break;
		}
	}
	unlock_orphan_inodes(cm_i);
}
/**
 *cc7 check_orphan_space:如果当前检查点管理器下孤立点所占空间是否大于最大孤立点空间
 *@sbi:指向当前版本下超级块信息的实例
 *@return:，如果是,则返回错误信息
 */
int check_orphan_space(struct hmfs_sb_info *sbi)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	int err = 0;

	lock_orphan_inodes(cm_i);
	if (cm_i->n_orphans >= HMFS_MAX_ORPHAN_NUM)
		err = -ENOSPC;
	BUG_ON(cm_i->n_orphans > HMFS_MAX_ORPHAN_NUM);
	unlock_orphan_inodes(cm_i);
	return err;
}
/**
 *cc8 sync_checkpoint_info:用给定检查点的版本信息和NAT树的根节点信息更新当前检查点信息
 *@sbi:指向当前版本下超级块信息的实例
 *@hmfs_cp：指向整个超级块的全局检查点的指针实例
 *@cp：指向当前版本下检查点的信息实例
 */
static void sync_checkpoint_info(struct hmfs_sb_info *sbi,
				struct hmfs_checkpoint *hmfs_cp,
				struct checkpoint_info *cp)
{
	cp->version = le32_to_cpu(hmfs_cp->checkpoint_ver);
	cp->nat_root = ADDR(sbi, le64_to_cpu(hmfs_cp->nat_addr));
	cp->cp = hmfs_cp;
}
/**
 *cc9 move_to_next_checkpoint：将新的检查点插入到CP树中
 *@sbi:指向当前版本下超级块信息的实例
 */
static void move_to_next_checkpoint(struct hmfs_sb_info *sbi,
				struct hmfs_checkpoint *prev_checkpoint)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);

	lock_cp_tree(cm_i);

	/**
	 *用给出的前一个检查点的信息更新当前检查点管理器的信息，插入新的版本号给当前检查点下的CP树的根节点，同时将当前检查点插入到CP树中
	 */
	sync_checkpoint_info(sbi, prev_checkpoint, cm_i->cur_cp_i);
	radix_tree_insert(&cm_i->cp_tree_root, cm_i->new_version,
			cm_i->cur_cp_i);
	list_add(&cm_i->cur_cp_i->list, &cm_i->last_cp_i->list);
	cm_i->new_version = next_checkpoint_ver(cm_i->new_version);
	cm_i->last_cp_i = cm_i->cur_cp_i;
retry:
	cm_i->cur_cp_i = kmem_cache_alloc(cp_info_entry_slab, GFP_KERNEL);

	if (!cm_i->cur_cp_i) {
		cond_resched();
		goto retry;
	}

	cm_i->cur_cp_i->version = cm_i->new_version;
	cm_i->cur_cp_i->nat_root = NULL;
	cm_i->cur_cp_i->cp = NULL;

	unlock_cp_tree(cm_i);
}
/**
 *cc10 get_next_checkpoint_info:从当前CP树种得到下一个检查点的信息
 *@sbi:指向当前版本下超级块信息的实例
 *@cp：指向当前版本下检查点的信息实例
 *@return:返回下一个检查点的实例
 */
struct checkpoint_info *get_next_checkpoint_info(struct hmfs_sb_info *sbi,
				struct checkpoint_info *cp_i)
{
	ver_t next_version;
	struct hmfs_checkpoint *this_cp, *next_cp;
	block_t next_addr;
	struct checkpoint_info *next_cp_i;
	struct hmfs_cm_info *cm_i = CM_I(sbi);

	/**
	 *找到当前检查点的下一个检查点的版本号是否与当前检查点树的根节点相同
	 */
	this_cp = cp_i->cp;
	next_addr = le64_to_cpu(this_cp->next_cp_addr);
	next_cp = ADDR(sbi, next_addr);
	next_version = le32_to_cpu(next_cp->checkpoint_ver);
	next_cp_i = radix_tree_lookup(&cm_i->cp_tree_root, next_version);

	if (!next_cp_i) {
retry:
		next_cp_i = kmem_cache_alloc(cp_info_entry_slab, GFP_KERNEL);
		if (!next_cp_i) {
			cond_resched();
			goto retry;
		}

		/**
		 *找到下一个版本号信息后相应地更新检查点信息，同时加入到CP树中，并且将下一个检查点的版本号插入到CP树中
		 */
		sync_checkpoint_info(sbi, next_cp, next_cp_i);
		//TODO: sort cp_i according to version
		list_add(&next_cp_i->list, &cm_i->last_cp_i->list);
		radix_tree_insert(&cm_i->cp_tree_root, next_cp_i->version,
				next_cp_i);
	}
	return next_cp_i;
}

/*
 * no_fail: If checkpoint with version is miss, return the checkpoint
 * whose version is slightly greater than version
 */
/**
 *cc11 get_checkpoint_info:如果不能给定版本的检查点，即视为丢失，则返回版本号距离跟定版本号最近的检查点
 *@sbi:指向当前版本下超级块信息的实例
 *@version:版本号
 *@no_fail:是否找到给定版本的检查点
 */
struct checkpoint_info *get_checkpoint_info(struct hmfs_sb_info *sbi,
				ver_t version, bool no_fail)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct checkpoint_info *cp_i, *entry;
	struct list_head *this, *head;
	struct hmfs_checkpoint *hmfs_cp;
	block_t next_addr;

	/**
	 * 返回当前最新的检查点信息，并且在CP树种查找给定版本号的检查点，如果没找到，就把上一个检查点的信息赋值给它
	 */
	if (version == cm_i->new_version)
		return cm_i->cur_cp_i;

	lock_cp_tree(cm_i);
	cp_i = radix_tree_lookup(&cm_i->cp_tree_root, version);
	if (!cp_i) {
		cp_i = cm_i->last_cp_i;
		hmfs_bug_on(sbi, version > cp_i->version);

		/**
		 * 如果当前的检查点的版本号丢失了，则找到改离该检查点最近的检查点信息，并且把其版本号赋值给丢失的版本号
		 */
		head = &cp_i->list;
		/* Search a checkpoint_info whose version is closest to given version */
		cp_i = NULL;
		list_for_each(this, head) {
			entry = list_entry(this, struct checkpoint_info, list);
			if (entry->version < version) {
				if (cp_i == NULL || entry->version > cp_i->version)
					cp_i = entry;
			}
		}

		if (cp_i == NULL)
			cp_i = cm_i->last_cp_i;

		do {
			next_addr = le64_to_cpu(cp_i->cp->next_cp_addr);

			hmfs_cp = ADDR(sbi, next_addr);
retry:
			entry = kmem_cache_alloc(cp_info_entry_slab, GFP_KERNEL);

			if (!entry) {
				cond_resched();
				goto retry;
			}

			/**
			 *同步下一个检查点及其entry信息，同时根据entry信息添加版本号到CP树
			 */
			sync_checkpoint_info(sbi, hmfs_cp, entry);

			list_add(&entry->list, &cm_i->last_cp_i->list);
			radix_tree_insert(&cm_i->cp_tree_root, entry->version,
					entry);
			cp_i = entry;
			if (cp_i->version == version || (no_fail && cp_i->version > version))
				break;
			if (cp_i->version > version) {
				cp_i = NULL;
				break;
			}
		} while (1);

	}
	unlock_cp_tree(cm_i);
	return cp_i;
}
/**
 *cc12 get_mnt_checkpoint:找到给出的版本号，并且返回其检查点所在的位置
 *@sbi:指向当前版本下超级块信息的实例
 *@cp:检查点实例
 *@version:版本号
 *@return:返回给定版本所在的检查点
 */
static struct hmfs_checkpoint *get_mnt_checkpoint(struct hmfs_sb_info *sbi,
				struct hmfs_checkpoint *cp,	ver_t version)
{
	struct hmfs_checkpoint *entry = cp;
	ver_t current_version;
	block_t addr;
	/**
	 *如果给出的版本号不等于下一个检查点中记录的版本号，就一直沿着当前版本号向下查找
	 */
	do {
		addr = le64_to_cpu(entry->next_cp_addr);
		entry = ADDR(sbi, addr);
		current_version = le32_to_cpu(entry->checkpoint_ver);
	} while(current_version != version && entry != cp);

	if (current_version == version)
		return entry;
	return NULL;
}
/**
 *cc13 check_checkpoint_state:检查当前检查点的状态，并采取相应操作
 *@sbi:指向当前版本下超级块信息的实例
 */
void check_checkpoint_state(struct hmfs_sb_info *sbi)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct hmfs_checkpoint *hmfs_cp = cm_i->last_cp_i->cp;
	u8 state;

	sbi->recovery_doing = 1;
	state = hmfs_cp->state;
	/**
	 *根据上一个检查点的状态信息，如果是正常状态，什么都不做；如果是收集垃圾的状态，
	 *则根据当前状态和上一个检查点恢复上一次垃圾收集，如果是redo，则重做上一次检查点以来的检查点工作；
	 *如果是删除一个检查点状态，则重做删除检查点操作
	 */
	switch(state) {
	case HMFS_NONE:
		goto out;
	case HMFS_GC:
		recovery_gc_crash(sbi, hmfs_cp);
		break;
	case HMFS_ADD_CP:
		redo_checkpoint(sbi, hmfs_cp);
		break;
	case HMFS_RM_CP:
		redo_delete_checkpoint(sbi);
		break;
	}
	set_fs_state(hmfs_cp, HMFS_NONE);
out:
	sbi->recovery_doing = 0;
}
/**
 *cc14 init_checkpoint_manager:初始化检查点管理器的各项信息
 *@sbi:指向当前版本下超级块信息的实例
 */
int init_checkpoint_manager(struct hmfs_sb_info *sbi)
{
	struct hmfs_cm_info *cm_i;
	struct checkpoint_info *cp_i;
	struct hmfs_super_block *super = ADDR(sbi, 0);
	struct hmfs_checkpoint *hmfs_cp;
	block_t cp_addr;

	/* Init checkpoint_info list */
	cp_addr = le64_to_cpu(super->cp_page_addr);
	hmfs_cp = ADDR(sbi, cp_addr);

	/**
	 * 如果超级块信息中的ro-mount版本号与起始检查点的版本号不相符，则找到其版本号所在的检查点，如果找不到返回参数无效
	 */
	if (sbi->mnt_cp_version && sbi->mnt_cp_version != 
			le32_to_cpu(hmfs_cp->checkpoint_ver)) {
		hmfs_cp = get_mnt_checkpoint(sbi, hmfs_cp, sbi->mnt_cp_version);
		if (!hmfs_cp)
			return -EINVAL;
	}

	cm_i = kzalloc(sizeof(struct hmfs_cm_info), GFP_KERNEL);

	if (!cm_i) {
		goto out_cm_i;
	}

	/* allocate and init last checkpoint_info */
	/**
	 *分配并且初始化上一次检查点的CP树链表信息
	 */
	cp_i = kmem_cache_alloc(cp_info_entry_slab, GFP_ATOMIC);
	if (!cp_i) {
		goto out_cp_i;
	}

	/**
	 *包括有效的inode，node,块数以及用户块数，用来初始化检查点管理器的信息，同时同步到检查点CP树
	 */
	cm_i->valid_inode_count = le32_to_cpu(hmfs_cp->valid_inode_count);
	cm_i->valid_node_count = le32_to_cpu(hmfs_cp->valid_node_count);
	cm_i->valid_block_count = le32_to_cpu(hmfs_cp->valid_block_count);
	cm_i->user_block_count = le32_to_cpu(HMFS_RAW_SUPER(sbi)->user_block_count);
	cm_i->alloc_block_count = le32_to_cpu(hmfs_cp->alloc_block_count);
	sync_checkpoint_info(sbi, hmfs_cp, cp_i);
	cm_i->last_cp_i = cp_i;

	spin_lock_init(&cm_i->cm_lock);
	INIT_LIST_HEAD(&cp_i->list);
	INIT_RADIX_TREE(&cm_i->cp_tree_root, GFP_ATOMIC);
	mutex_init(&cm_i->cp_tree_lock);

	lock_cp_tree(cm_i);
	radix_tree_insert(&cm_i->cp_tree_root, cp_i->version, cp_i);
	unlock_cp_tree(cm_i);

	/* Allocate and Init current checkpoint_info */
	/**
	 *分配并且初始化当前的检查点树
	 */
	cp_i = kmem_cache_alloc(cp_info_entry_slab, GFP_KERNEL);
	INIT_LIST_HEAD(&cp_i->list);
	cm_i->new_version = next_checkpoint_ver(le32_to_cpu(hmfs_cp->checkpoint_ver));
	cp_i->version = cm_i->new_version;
	cp_i->nat_root = NULL;
	cp_i->cp = NULL;

	init_orphan_manager(cm_i);

	cm_i->cur_cp_i = cp_i;

	sbi->cm_info = cm_i;
	return 0;

out_cp_i:
	kfree(cm_i);
out_cm_i:
	return -ENOMEM;
}
/**
 * cc15 destroy_checkpoint_info:销毁处理删除链表的检查点信息
 *cm_i:检查点管理器的实例
 */
static void destroy_checkpoint_info(struct hmfs_cm_info *cm_i)
{
	struct checkpoint_info *cp_i = cm_i->last_cp_i, *entry;
	struct list_head *head, *this, *tmp;

	/**
	 *删除处于移除链表队列的检查点entry,同时从CP树中删除其版本号，
	 */
	head = &cp_i->list;
	list_for_each_safe(this, tmp, head) {
		entry = list_entry(this, struct checkpoint_info, list);
		list_del(this);
		INIT_LIST_HEAD(&entry->list);
		radix_tree_delete(&cm_i->cp_tree_root, entry->version);
		kmem_cache_free(cp_info_entry_slab, entry);
	}
	kmem_cache_free(cp_info_entry_slab, cp_i);
	radix_tree_delete(&cm_i->cp_tree_root, cp_i->version);
	kmem_cache_free(cp_info_entry_slab, cm_i->cur_cp_i);
}
/**
 *cc16 destroy_checkpoint_manager:销毁检查点管理器所占的空间并且释放其所占空间
 *@sbi:指向当前版本下超级块信息的实例
 *@return:成功返回0
 */
int destroy_checkpoint_manager(struct hmfs_sb_info *sbi)
{
	struct hmfs_cm_info *cm_i = sbi->cm_info;

	lock_cp_tree(cm_i);
	destroy_checkpoint_info(cm_i);
	unlock_cp_tree(cm_i);

	kfree(cm_i);
	return 0;
}
/**
 *cc17 create_checkpoint_caches:创建检查点缓存实例
 *@return:成功返回0；出错返回超出内存
 */
int create_checkpoint_caches(void)
{
	orphan_entry_slab = hmfs_kmem_cache_create("hmfs_orphan_entry",
								sizeof(struct orphan_inode_entry), NULL);
	if (unlikely(!orphan_entry_slab))
		return -ENOMEM;

	cp_info_entry_slab = hmfs_kmem_cache_create("hmfs_checkpoint_info_entry",
								sizeof(struct checkpoint_info), NULL);
	if (cp_info_entry_slab == NULL) {
		goto free_orphan;
	}
	
	return 0;

free_orphan:
	kmem_cache_destroy(orphan_entry_slab);
	
	return -ENOMEM;
}
/**
 *cc18 destroy_checkpoint_caches:释放孤立entry集合和检查点信息entry集合所占空间
 */
void destroy_checkpoint_caches(void)
{
	kmem_cache_destroy(orphan_entry_slab);
	kmem_cache_destroy(cp_info_entry_slab);
}
/**
 *cc19 sync_dirty_inodes:同步处于链表中的脏的inode信息
 *@sbi:指向当前版本下超级块信息的实例
 *@return:成功返回0，失败返回错误标识
 */
static int sync_dirty_inodes(struct hmfs_sb_info *sbi)
{
	struct list_head *head, *this, *next;
	struct hmfs_inode_info *fi;
	int ret;
	/**
	 * 获取脏的inode链表的队头，并且从inode链表中写入脏的inode
	 */
	head = &sbi->dirty_inodes_list;
	list_for_each_safe(this, next, head) {
		fi = list_entry(this, struct hmfs_inode_info, list);
		ret = __hmfs_write_inode(&fi->vfs_inode, true);
		if (ret == -ENOSPC)
			return -ENOSPC;
	}
	return 0;
}
/**
 *cc20 block_operations: 对脏的inode块进行处理
 *@sbi:指向当前版本下超级块信息的实例
 *@return:成功返回0
 */
static int block_operations(struct hmfs_sb_info *sbi)
{
	int ret = 0;

	/**
	 *依次处理脏的inode链表上的块，并且同步脏的inode块的信息，如果成功，返回标识，依次进行处理
	 */
retry:
	mutex_lock_all(sbi);
		
	if (!list_empty(&sbi->dirty_inodes_list)) {
		mutex_unlock_all(sbi);
		ret = sync_dirty_inodes(sbi);
		if (ret)
			return ret;
		goto retry;
	}

	return 0;
}
/**
 *cc21 unblock_operations:释放处于超级块环境中所有的mutex
 */
static void unblock_operations(struct hmfs_sb_info *sbi)
{
	mutex_unlock_all(sbi);
}

/*
 * We need to flush orphan inodes before allocating the checkpoint block of
 * this orphan inodes. In GC, we would collect block by order. If we allocate
 * checkpoint block before orphan blocks adn they are in the same segment,
 * we would move the checkpoint to the new segment first, and then if we move the
 * orphan blocks, we would write address to older checkpoint instead 
 * of new checkpoint
 */
/**
 *cc22 flush_orphan_inodes:
 *@sbi:指向当前版本下超级块信息的实例
 */
static int flush_orphan_inodes(struct hmfs_sb_info *sbi, block_t *orphan_addrs)
{
	struct list_head *head, *this;
	struct orphan_inode_entry *entry;
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct hmfs_summary *summary;
	block_t orphan_addr = 0;
	__le32 *orphan_block = NULL;
	__le32 *end = NULL;
	int i = 0;
	int ret = 0;


	lock_orphan_inodes(cm_i);
	head = &cm_i->orphan_inode_list;
	list_for_each(this, head) {
		/**
		 *找到孤立链表中的每一个inode点，并未它们分配新的块
		 */
		entry = list_entry(this, struct orphan_inode_entry, list);
		if (!orphan_addr) {
			orphan_block = alloc_new_node(sbi, 0, NULL, SUM_TYPE_CP, true);
			if (IS_ERR(orphan_block)) {
				ret = -ENOMEM;
				goto out;
			}
			/**
			 *为每一个孤立块做相同的操作，找到孤立块的summary表，并为其更新最新的版本号
			 */
			orphan_addr = L_ADDR(sbi, orphan_block);
			summary = get_summary_by_addr(sbi, orphan_addr);
			make_summary_entry(summary, 0, cm_i->new_version, i,
					SUM_TYPE_ORPHAN);
			orphan_addrs[i++] = orphan_addr;
			orphan_block = ADDR(sbi, orphan_addr);
			/* Reseverd for checkpoint address */
			end = (__le32 *)JUMP(orphan_block, HMFS_PAGE_SIZE);
			orphan_block = (__le32 *)JUMP(orphan_block, sizeof(__le64));
		}
		*orphan_block = cpu_to_le32(entry->ino);
		orphan_block++;
		if (orphan_block == end) {
			orphan_addr = 0;
		}
	}
	hmfs_bug_on(sbi, i > NUM_ORPHAN_BLOCKS);
out:
	unlock_orphan_inodes(cm_i);
	return ret;
}
/**
 * cc23 flush_orphan_inodes_finish:刷新回所有的孤立节点
 *@sbi:指向当前版本下超级块信息的实例
 *@orphan_addrs:所有孤立节点的集合
 *@cp_addr：检查点的地址
 */
static void flush_orphan_inodes_finish(struct hmfs_sb_info *sbi, 
				block_t *orphan_addrs, block_t cp_addr)
{
	int i;
	__le64 *orphan_block;
	struct hmfs_checkpoint *hmfs_cp = ADDR(sbi, cp_addr);

    /**
     *依次遍历所有孤立节点的地址，并且将它们对应刷新回检查点下孤立节点集合中
     */
	for (i = 0; i < NUM_ORPHAN_BLOCKS; ++i, orphan_addrs++) {
		if (*orphan_addrs) {
			orphan_block = ADDR(sbi, *orphan_addrs);
			*orphan_block = cpu_to_le64(cp_addr);
			hmfs_cp->orphan_addrs[i] = cpu_to_le64(*orphan_addrs);
		} else
			break;
	}
}
/**
 *cc24 recover_orphan_inode:根据inode号获取inode，并且清零链表
 *@sbi:指向当前版本下超级块信息的实例
 *@ino:inode ID号
 */
static void recover_orphan_inode(struct hmfs_sb_info *sbi, nid_t ino)
{
	struct inode *inode = hmfs_iget(sbi->sb, ino);
	hmfs_bug_on(sbi, IS_ERR(inode));
	clear_nlink(inode);

	iput(inode);
}

/* Now we delete the orphan inodes */
/**
 *cc25 recover_orphan_inodes:根据当前超级块地址相应删除对应的孤立节点
 *@sbi:指向当前版本下超级块信息的实例
 *@return:成功返回0
 */
int recover_orphan_inodes(struct hmfs_sb_info *sbi)
{
	int i;
	__le32 *orphan_block;
	__le32 *end;
	block_t orphan_addr;
	nid_t ino;
	struct hmfs_checkpoint *hmfs_cp = CM_I(sbi)->last_cp_i->cp;

    /**
     *依次找到孤立节点地址中的每一个孤立块，并且删除相应的孤立节点
     */
	for (i = 0; i < NUM_ORPHAN_BLOCKS; ++i) {
		orphan_addr = le64_to_cpu(hmfs_cp->orphan_addrs[i]);
		if (!orphan_addr)
			return 0;
		orphan_block = ADDR(sbi, orphan_addr);
		end = (__le32 *)JUMP(orphan_block, HMFS_PAGE_SIZE);
		orphan_block = (__le32 *)JUMP(orphan_block, sizeof(__le64));
		while (orphan_block != end) {
			ino = le32_to_cpu(*orphan_block);
			recover_orphan_inode(sbi, ino);
			orphan_block++;
		}
	}

	return 0;
}
/**
 *cc26 do_checkpoint: 进行相应地检查点备份工作
 *@sbi:指向当前版本下超级块信息的实例
 *@return:成功返回0
 */
static int do_checkpoint(struct hmfs_sb_info *sbi)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct free_segmap_info *free_i = FREE_I(sbi);
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct hmfs_super_block *raw_super = HMFS_RAW_SUPER(sbi);
	struct hmfs_summary *summary;
	unsigned int sb_checksum;
	ver_t store_version;
	block_t store_checkpoint_addr = 0;
	block_t nat_root_addr, orphan_addrs[2] = {0, 0};
	struct hmfs_nat_node *nat_root = NULL;
	struct hmfs_checkpoint *prev_checkpoint, *next_checkpoint;
	struct hmfs_checkpoint *store_checkpoint;
	struct curseg_info *curseg_i = SM_I(sbi)->curseg_array;
	int ret;

	prev_checkpoint = cm_i->last_cp_i->cp;
	next_checkpoint = ADDR(sbi, le64_to_cpu(prev_checkpoint->next_cp_addr));

	/* 1. set new cp block */
	/**
	 * 设置并分配新的检查点块，记录新的检查点版本号
	 */
	ret = flush_orphan_inodes(sbi, orphan_addrs);

	store_version = cm_i->new_version;
	store_checkpoint = alloc_new_node(sbi, 0, NULL, SUM_TYPE_CP, true);

	if (IS_ERR(store_checkpoint)) {
		hmfs_dbg("\n");
		return -ENOSPC;
	}
    /**
     *根据检查点的地址相应地更新summary表中的版本号
     */
	store_checkpoint_addr = L_ADDR(sbi, store_checkpoint);
	summary = get_summary_by_addr(sbi, store_checkpoint_addr);
	make_summary_entry(summary, 0, cm_i->new_version, 0, SUM_TYPE_CP);

	/* GC process should not update nat tree */
	/**
	 *垃圾收集过程中不应该更新NAT树
	 */
	nat_root = flush_nat_entries(sbi, store_checkpoint);
	if (IS_ERR(nat_root))
		return PTR_ERR(nat_root);
	nat_root_addr = L_ADDR(sbi, nat_root);

	flush_orphan_inodes_finish(sbi, orphan_addrs, store_checkpoint_addr);
    /**
     * 更新新的检查点的前后检查点信息和NAT根的信息，将检查点管理器中的有效inode数、块数、分配块数等信息更新会最新的检查点中
     */
	store_checkpoint = ADDR(sbi, store_checkpoint_addr);
	store_checkpoint->next_cp_addr = prev_checkpoint->next_cp_addr;
	store_checkpoint->prev_cp_addr = next_checkpoint->prev_cp_addr;
	set_struct(store_checkpoint, nat_addr, nat_root_addr);

	set_struct(store_checkpoint, checkpoint_ver, store_version);
	set_struct(store_checkpoint, valid_block_count, cm_i->valid_block_count);
	set_struct(store_checkpoint, valid_inode_count, cm_i->valid_inode_count);
	set_struct(store_checkpoint, valid_node_count, cm_i->valid_node_count);
	set_struct(store_checkpoint, alloc_block_count, cm_i->alloc_block_count);
	set_struct(store_checkpoint, free_segment_count, free_i->free_segments);
	set_struct(store_checkpoint, cur_node_segno, 
			atomic_read(&curseg_i[CURSEG_NODE].segno));
	set_struct(store_checkpoint, cur_node_blkoff,
			curseg_i[CURSEG_NODE].next_blkoff);
	set_struct(store_checkpoint, cur_data_segno,
			atomic_read(&curseg_i[CURSEG_DATA].segno));
	set_struct(store_checkpoint, cur_data_blkoff,
			curseg_i[CURSEG_DATA].next_blkoff);
	set_struct(store_checkpoint, next_scan_nid, nm_i->next_scan_nid);
	set_struct(store_checkpoint, elapsed_time, get_mtime(sbi));

	/* 2. flush SIT to cp */
	/**
	 * 刷新SIT信息回检查点中
	 */
	flush_sit_entries(sbi, store_checkpoint_addr, nat_root);
	set_summary_valid_bit(summary);

	/* 6. connect to super */
	/**
	 * 连接回超级块中
	 */
	hmfs_memcpy_atomic(&prev_checkpoint->next_cp_addr, 
			&store_checkpoint_addr, 8);
	hmfs_memcpy_atomic(&next_checkpoint->prev_cp_addr,
			&store_checkpoint_addr, 8);
	hmfs_memcpy_atomic(&raw_super->cp_page_addr, &store_checkpoint_addr, 8);
	sb_checksum = hmfs_make_checksum(raw_super);

	set_struct(raw_super, checksum, sb_checksum);
	
	//TODO: memory barrier?
	raw_super = next_super_block(raw_super);
	hmfs_memcpy(raw_super, HMFS_RAW_SUPER(sbi), sizeof(struct hmfs_super_block));

	/* clear last checkpoint state and logs */
	/**
	 *最后清楚上一个检查点状态及相应日志
	 */
	set_fs_state(prev_checkpoint, HMFS_NONE);
	if (prev_checkpoint->nr_gc_segs)
		prev_checkpoint->nr_gc_segs = 0;

	//FIXME:
	/**
	 对下一个检查点做类似炒作，并且释放空间
	 */
	migrate_mmap_block(sbi);
	move_to_next_checkpoint(sbi, store_checkpoint);

	free_prefree_segments(sbi);
	reinit_gc_logs(sbi);
	return 0;
}
/**
 *cc27 write_checkpoint:对所有脏的inode进行检查点写的操作
 *@sbi:指向当前版本下超级块信息的实例
 *@return:成功返回0
 */
int write_checkpoint(struct hmfs_sb_info *sbi, bool unlock)
{
	struct sit_info *sit_i = SIT_I(sbi);
	int ret;
    /**
     * 对所有脏的inode进行记录和信息同步处理
     */
	ret = block_operations(sbi);
	if (ret)
		return ret;

	if (!sit_i->dirty_sentries) {
		ret = 0;
		goto unlock;
	}

	ret = do_checkpoint(sbi);

unlock:
	if (unlock) {
		unblock_operations(sbi);
	}
	return ret;
}

int redo_checkpoint(struct hmfs_sb_info *sbi, struct hmfs_checkpoint *prev_cp)
{
	//XXX:after sbi initilization?
	struct hmfs_super_block *raw_super = HMFS_RAW_SUPER(sbi);
	struct hmfs_summary *summary;
	unsigned int sb_checksum;
	block_t store_cp_addr = 0;
	struct hmfs_checkpoint *next_cp;
	struct hmfs_checkpoint *store_cp;
	ver_t store_version;
	void *nat_root;

	/* 1. restore addr */
	store_cp_addr = le64_to_cpu(prev_cp->state_arg_2);
	store_cp = ADDR(sbi, store_cp_addr);

	hmfs_bug_on(sbi, L_ADDR(sbi, prev_cp)!=
			le64_to_cpu(store_cp->prev_cp_addr));

	summary = get_summary_by_addr(sbi, store_cp_addr);
	set_summary_valid_bit(summary);

	/* 2. flush cp-inlined SIT journal */
	recovery_sit_entries(sbi, prev_cp);

	/* 3. mark valid */
	store_version = le32_to_cpu(store_cp->checkpoint_ver);
	nat_root = ADDR(sbi, le32_to_cpu(store_cp->nat_addr));
	mark_block_valid(sbi, nat_root, store_cp);

	/* 4. connect to super */
	next_cp = ADDR(sbi, le64_to_cpu(store_cp->next_cp_addr));
	hmfs_memcpy_atomic(&prev_cp->next_cp_addr, &store_cp_addr, 8);
	hmfs_memcpy_atomic(&next_cp->prev_cp_addr, &store_cp_addr, 8);
	hmfs_memcpy_atomic(&raw_super->cp_page_addr, &store_cp_addr, 8);
	sb_checksum = hmfs_make_checksum(raw_super);
	set_struct(raw_super, checksum, sb_checksum);
	
	//TODO: memory barrier?
	raw_super = next_super_block(raw_super);
	hmfs_memcpy(raw_super, ADDR(sbi, 0), sizeof(struct hmfs_super_block));
	
	if (prev_cp->nr_gc_segs)
		prev_cp->nr_gc_segs = 0;

	move_to_next_checkpoint(sbi, store_cp);
	reinit_gc_logs(sbi);
	return 0;
}

/* Clear summary bit and update SIT valid blocks */
static void invalidate_block(struct hmfs_sb_info *sbi, block_t addr,
				struct hmfs_summary *summary)
{
	clear_summary_valid_bit(summary);
	update_sit_entry(sbi, GET_SEGNO(sbi, addr), -1);
}

static int __delete_checkpoint(struct hmfs_sb_info *sbi, void *cur_node,
				void *next_node, ver_t prev_ver, ver_t next_ver)
{
	ver_t cur_node_ver, next_node_ver;
	struct hmfs_summary *cur_sum, *next_sum;
	bool delete_this = false;
	int i;

	cur_sum = get_summary_by_addr(sbi, L_ADDR(sbi, cur_node));
	cur_node_ver = get_summary_start_version(cur_sum);
	if (!next_node) {
		delete_this = cur_node_ver > prev_ver;
		next_sum = NULL;
		goto delete;	
	}

	next_sum = get_summary_by_addr(sbi, L_ADDR(sbi, next_node));
	next_node_ver = get_summary_start_version(next_sum);

	/* this block is COW */
	if (cur_node_ver != next_node_ver) {
		hmfs_bug_on(sbi, cur_node_ver > next_node_ver);
		/* Not any previous checkpoint refer to this block */
		if (cur_node_ver > prev_ver) {
			delete_this = true;
		}
	} else {	/* This block is shared */
		/* If not any previous checkpoint refer to this block */
		if (cur_node_ver > prev_ver) {
			set_summary_start_version(cur_sum, next_ver);
		}
		return 0;
	}
	
delete:
	if (delete_this) {
		/* Invalidate this block */
		invalidate_block(sbi, L_ADDR(sbi, cur_node), cur_sum);
	}

	switch (get_summary_type(cur_sum)) {
	case SUM_TYPE_NATN: {
		__le64 *cur_child, *next_child;

		cur_child = HMFS_NAT_NODE(cur_node)->addr;
		next_child = next_node ? HMFS_NAT_NODE(next_node)->addr : NULL;

		for (i = 0; i < NAT_ADDR_PER_NODE; i++, cur_child++,
				next_child = next_child ? next_child + 1 : NULL) {
			if (!*cur_child)
				continue;
			cur_node = ADDR(sbi, le64_to_cpu(*cur_child));
			next_node = next_child ? ADDR(sbi, le64_to_cpu(*next_child)) 
					: NULL;
			__delete_checkpoint(sbi, cur_node, next_node, prev_ver, next_ver);
		}
		return 0;
	}

	case SUM_TYPE_NATD: {
		struct hmfs_nat_entry *cur_entry, *next_entry;
		void *cur_child, *next_child;

		cur_entry = HMFS_NAT_BLOCK(cur_node)->entries;
		next_entry = next_node ? HMFS_NAT_BLOCK(next_node)->entries : NULL;

		for (i = 0; i < NAT_ENTRY_PER_BLOCK; i++, cur_entry++,
				next_entry = next_entry ? next_entry + 1 : NULL) {
			if (!cur_entry->ino)
				continue;
			cur_child = ADDR(sbi, le64_to_cpu(cur_entry->block_addr));
			next_child = next_entry ? 
					ADDR(sbi, le64_to_cpu(next_entry->block_addr)) : NULL;
			__delete_checkpoint(sbi, cur_child, next_child, prev_ver,
					next_ver);
		}
		return 0;
	}

	case SUM_TYPE_INODE: {
		struct hmfs_inode *cur_inode, *next_inode;
		void *cur_child, *next_child;
		__le64 *cur_db, *next_db;
		block_t xaddr;

		/*
		 * If next_node is not inode, then child of cur_node 
		 * is deleted base on previous checkpoint
		 */
		if (next_sum && get_summary_type(next_sum) != SUM_TYPE_INODE) {
			next_node = NULL;
		}
		cur_inode = (struct hmfs_inode *)cur_node;
		next_inode = (struct hmfs_inode *)next_node;

		/* Delete extended data block */
		for_each_xblock(cur_inode, xaddr, i) {
			if (!xaddr)
				continue;
			cur_child = ADDR(sbi, xaddr);
			next_child = next_node ? 
					ADDR(sbi, XBLOCK_ADDR(next_inode, xblock_tags[i])) : NULL;
			__delete_checkpoint(sbi, cur_child, next_child, prev_ver,
					next_ver);
		}
		
		/* Delete data blocks */
		cur_db = cur_inode->i_addr;
		next_db = next_node ? next_inode->i_addr : NULL;
		for (i = 0; i < NORMAL_ADDRS_PER_INODE; i++,
				cur_db++, next_db = next_db ? next_db + 1 : NULL) {
			if (!*cur_db)
				continue;
			cur_child = ADDR(sbi, le64_to_cpu(*cur_db));
			next_child = next_db ? ADDR(sbi, le64_to_cpu(*next_db)) : NULL;
			__delete_checkpoint(sbi, cur_child, next_child, prev_ver, 
					next_ver);
		}

		/* We don't need to handle nid. Because they are in NAT entry block, too */
	}
	
	case SUM_TYPE_DN: {
		__le64 *cur_db, *next_db;
		struct direct_node *cur_dn, *next_dn;
		void *cur_child, *next_child;

		/* 
		 * If next_node is not direct node, the this node has been deleted
		 * in next checkpoint. And the child of cur_node is deleted based on
		 * previous checkpoint 
		 */
		if (next_sum && get_summary_type(next_sum) != SUM_TYPE_DN) {
			next_node = NULL;
		}
		cur_dn = DIRECT_NODE(cur_node);
		next_dn = DIRECT_NODE(next_node);
		
		cur_db = cur_dn->addr;
		next_db = next_node ? next_dn->addr : NULL;
		for (i = 0; i < ADDRS_PER_BLOCK; i++, cur_db++,
				next_db = next_db ? next_db + 1 : NULL) {
			if (!*cur_db)
				continue;
			cur_child = ADDR(sbi, le64_to_cpu(*cur_db));
			next_child = next_db ? ADDR(sbi, le64_to_cpu(*next_db)) : NULL;
			__delete_checkpoint(sbi, cur_child, next_child, prev_ver, 
					next_ver);
		}
		return 0;
	}
	case SUM_TYPE_ORPHAN:
	case SUM_TYPE_CP:
		hmfs_bug_on(sbi, 1);
		return 1;
	case SUM_TYPE_IDN:
	case SUM_TYPE_DATA:
	case SUM_TYPE_XDATA:
		return 0;
	default:
		hmfs_bug_on(sbi, 1);
		return 1;
	}
}

static int do_delete_checkpoint(struct hmfs_sb_info *sbi, block_t cur_addr)
{
	struct hmfs_checkpoint *next_cp, *prev_cp, *last_cp, *cur_cp;
	struct hmfs_nat_node *cur_root, *next_root;
	int i;
	struct hmfs_summary *summary;
	block_t orphan_addr;
	ver_t prev_ver, next_ver;
	int ret = 0;
	struct hmfs_super_block *raw_super;
	block_t prev_addr, next_addr;

	cur_cp = ADDR(sbi, cur_addr);
	next_cp = ADDR(sbi, le64_to_cpu(cur_cp->next_cp_addr));
	prev_cp = ADDR(sbi, le64_to_cpu(cur_cp->prev_cp_addr));
	last_cp = CM_I(sbi)->last_cp_i->cp;

	if (cur_cp == prev_cp) {
		/* Only 1 valid checkpoint */
		hmfs_bug_on(sbi, cur_cp != next_cp);
		return -ENODATA; 
	}

	if (cur_cp == last_cp) {
		/* We want to delete the newest checkpoint */
		next_root = NULL;
		next_ver = HMFS_DEF_DEAD_VER;
	} else {
		next_root = ADDR(sbi, le64_to_cpu(next_cp->nat_addr));
		next_ver = le32_to_cpu(next_cp->checkpoint_ver);
	}

	if (prev_cp == last_cp) {
		/* We want to delete the oldest checkpoint */
		prev_ver = HMFS_DEF_DEAD_VER;
	} else {
		prev_ver = le32_to_cpu(prev_cp->checkpoint_ver);
	}

	set_fs_state(last_cp, HMFS_RM_CP);
	set_fs_state_arg(last_cp, cur_addr);

	cur_root = ADDR(sbi, le64_to_cpu(cur_cp->nat_addr));
	ret = __delete_checkpoint(sbi, cur_root, next_root,
				prev_ver, next_ver);

	/* Delete orphan blocks */
	for (i = 0; i < NUM_ORPHAN_BLOCKS; i++) {
		if (!cur_cp->orphan_addrs[i])
			break;
		orphan_addr = le64_to_cpu(cur_cp->orphan_addrs[i]);
		summary = get_summary_by_addr(sbi, orphan_addr);
		invalidate_block(sbi, orphan_addr, summary);
	}

	/* Delete checkpoint block */
	summary = get_summary_by_addr(sbi, cur_addr);
	invalidate_block(sbi, cur_addr, summary);

	/* Set valid bit of deleted blocks */
	flush_sit_entries_rmcp(sbi);

	/* Link cp list */
	prev_addr = cur_cp->prev_cp_addr;
	next_addr = cur_cp->next_cp_addr;
	next_cp->prev_cp_addr = cur_cp->prev_cp_addr;
	prev_cp->next_cp_addr = cur_cp->next_cp_addr;

	/* If delete newest checkpoint, we should modify super block */
	if (next_root == NULL) {
		set_fs_state(prev_cp, HMFS_NONE);
		raw_super = HMFS_RAW_SUPER(sbi);
		raw_super->cp_page_addr = cpu_to_le64(L_ADDR(sbi, prev_cp));
		raw_super->checksum = cpu_to_le16(hmfs_make_checksum(raw_super));
		raw_super = next_super_block(raw_super);
		hmfs_memcpy(raw_super, HMFS_RAW_SUPER(sbi), 
				sizeof(struct hmfs_super_block));
	}

	return 0;
}

int delete_checkpoint(struct hmfs_sb_info *sbi, ver_t version)
{
	struct checkpoint_info *del_cp_i = NULL;
	int ret = 0;

	del_cp_i = get_checkpoint_info(sbi, version, false);
	if (!del_cp_i)
		return -EINVAL;

	lock_gc(sbi);
	ret = write_checkpoint(sbi, false);
	ret = do_delete_checkpoint(sbi, L_ADDR(sbi, del_cp_i->cp));
	unblock_operations(sbi);
	unlock_gc(sbi);
	return ret;
}

int redo_delete_checkpoint(struct hmfs_sb_info *sbi)
{
	block_t cp_addr;

	cp_addr = le64_to_cpu(CM_I(sbi)->last_cp_i->cp->state_arg);
	return do_delete_checkpoint(sbi, cp_addr);
}
