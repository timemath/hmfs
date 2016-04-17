/*
 * fs/hmfs/file.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 * Copyright (c) 2015 SJTU RadLab
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/mm.h>
#include <linux/kernel.h>
#include <linux/falloc.h>
#include <linux/time.h>
#include <linux/stat.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/mount.h>
#include <linux/compat.h>
#include <linux/xattr.h>
#include <uapi/linux/magic.h>

#include "hmfs_fs.h"
#include "hmfs.h"
#include "segment.h"
#include "util.h"

#ifdef CONFIG_HMFS_FAST_READ
static struct kmem_cache *ro_file_address_cachep;
#endif
/*
 * 程威宇的注释
 */
static struct kmem_cache *mmap_block_slab;

static unsigned int start_block(unsigned int i, int level)
{
	if (level)
		return i - ((i - NORMAL_ADDRS_PER_INODE) % ADDRS_PER_BLOCK);
	return 0;
}
/*
 * 减小有效块数
 * 将inode指向文件的占有块数减小count个
 * 同时使sbi对应超级块占有的有效块数减小count个
 */
static int dec_valid_block_count(struct hmfs_sb_info *sbi,
				struct inode *inode, int count)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);

	lock_cm(cm_i);
	inode->i_blocks -= count;
	cm_i->valid_block_count -= count;
	unlock_cm(cm_i);

	return 0;
}

/* Find the last index of data block which is meaningful*/
unsigned int hmfs_dir_seek_data_reverse(struct inode *dir, unsigned int end_blk)
{
	struct dnode_of_data dn;
	struct direct_node *direct_node = NULL;
	struct hmfs_inode *inode_block = NULL;
	int err, j;
	block_t addr;
	unsigned start_blk;

	hmfs_bug_on(HMFS_I_SB(dir), is_inline_inode(dir));
	set_new_dnode(&dn, dir, NULL, NULL, 0);
	while (end_blk >= 0) {
		dn.node_block = NULL;
		dn.nid = 0;
		err = get_dnode_of_data(&dn, end_blk, LOOKUP_NODE);
		if (err) {
			if (dn.level)
				end_blk = start_block(end_blk, dn.level) - 1;
			else
				hmfs_bug_on(HMFS_I_SB(dir), 1);
			continue;
		}
		start_blk = start_block(end_blk, dn.level);
		if (dn.level) {
			direct_node = dn.node_block;
			hmfs_bug_on(HMFS_I_SB(dir), !direct_node);

			for (j = end_blk - start_blk; j >= 0; j--) {
				addr = le64_to_cpu(direct_node->addr[j]);
				if (addr)
					return start_blk + j;
			}
		} else {
			inode_block = dn.inode_block;
			hmfs_bug_on(HMFS_I_SB(dir), !inode_block);

			for (j = end_blk - start_blk; j >= 0; j--) {
				addr = le64_to_cpu(inode_block->i_addr[j]);
				if (addr)
					return start_blk + j;
			}
		}
		end_blk = start_blk - 1;
	}
	hmfs_bug_on(HMFS_I_SB(dir), 1);
	return 0;
}

/*
 * I think it's ok to seek hole or data but not to obtain a fs lock,
 * i.e. user could seek hole or data of file when fs is doing checkpoint
 */
/*寻找文件中的非孔区域或孔区域的位置
 *inode对应文件 end_blk为文件占用block数 start_pos为开始搜索的位置相对于文件开头的偏移量
 *type为SEEK_HOLE时搜索孔位置
 *type为SEEK_DATA时搜索非孔位置
 *返回值为对应位置起始处相对于文件起始处的block偏移数
 */

static unsigned int hmfs_file_seek_hole_data(struct inode *inode, 
				unsigned int end_blk, unsigned int start_pos, char type)
{
	int i = start_pos >> HMFS_PAGE_SIZE_BITS, j = 0;
	struct dnode_of_data dn;
	struct direct_node *direct_node = NULL;
	struct hmfs_inode *inode_block = NULL;
	int err;
	unsigned start_blk = end_blk;
	block_t addr;

	set_new_dnode(&dn, inode, NULL, NULL, 0);
	while (i < end_blk) {
		dn.node_block = NULL;
		dn.nid = 0;
		err = get_dnode_of_data(&dn, i, LOOKUP_NODE);
		if (err) {
			if (type == SEEK_HOLE)
				return start_block(i, dn.level);
			if (dn.level)
				i = start_block(i, dn.level) + ADDRS_PER_BLOCK;
			else 
				hmfs_bug_on(HMFS_I_SB(inode), 1);
			continue;
		}
	
		start_blk = start_block(i, dn.level);
		if (dn.level) {
			direct_node = dn.node_block;
			hmfs_bug_on(HMFS_I_SB(inode), !direct_node);

			for (j = start_blk - i; j < ADDRS_PER_BLOCK; j++) {
				addr = le64_to_cpu(direct_node->addr[j]);
				if (!addr && type == SEEK_HOLE)
					goto found;
				else if (addr && type == SEEK_DATA)
					goto found;
			}
			i = start_blk + ADDRS_PER_BLOCK;
		} else {
			/* level 0, inode */
			inode_block = dn.inode_block;
			hmfs_bug_on(HMFS_I_SB(inode), !inode_block);

			for (j = start_blk - i; j < NORMAL_ADDRS_PER_INODE; j++) {
				addr = le64_to_cpu(inode_block->i_addr[j]);
				if (!addr && type == SEEK_HOLE)
					goto found;
				else if (addr && type == SEEK_DATA)
					goto found;
			}
			i = start_blk + NORMAL_ADDRS_PER_INODE;
		}
	}
found:
	return start_blk + j < end_blk? start_blk + j : end_blk;
}
/*
 * 读取filp指向的文件,buf指向缓冲区，len为读取的长度,ppos指向读取位置的偏移量
 * 实现时先通过inode判断是否为inode内嵌文件，再分别通过不同过程进行读取
 */
static ssize_t __hmfs_xip_file_read(struct file *filp, char __user *buf,
				size_t len, loff_t *ppos)
{
	/* from do_XIP_mapping_read */
	struct inode *inode = filp->f_inode;
	pgoff_t index, end_index;
	unsigned long offset;
	loff_t isize, pos;
	size_t copied = 0, error = 0;
	struct hmfs_inode *inode_block;

	pos = *ppos;
	isize = i_size_read(inode);

	if (is_inline_inode(inode)) {
		inode_block = get_node(HMFS_I_SB(inode), inode->i_ino);
		if (IS_ERR(inode_block)) {
			error = PTR_ERR(inode_block);
			goto out;
		}
/*
 * 若读取位置加上长度不大于文件大小，则读取对应长度的内容
 * 否则只读取该位置之后的所有内容
 */
		if (pos + len > isize)
			copied = isize - pos;
		else
			copied = len;
/*将inode内嵌文件的指定位置和长度的内容加载到缓冲区*/
		if (__copy_to_user(buf, (__u8 *)inode_block->inline_content + pos,
					copied)) {
			copied = 0;
			error = -EFAULT;
		}
		goto out;
	}

	index = pos >> HMFS_PAGE_SIZE_BITS;	
	offset = pos & ~HMFS_PAGE_MASK;

	end_index = (isize - 1) >> HMFS_PAGE_SIZE_BITS;

	/*
	 * nr : read length for this loop
	 * offset : start inner-blk offset this loop
	 * index : start inner-file blk number this loop
	 * copied : read length so far
	 */
	/*根据pos和len，计算出块索引和偏移量，再按块进行读取直到全部读取完*/
	do {
		unsigned long nr, left;
		void *xip_mem[1];
		int zero = 0;
		int size;

		/* nr is the maximum number of bytes to copy from this page */
		nr = HMFS_PAGE_SIZE;	//HMFS_SIZE
		if (index >= end_index) {
			if (index > end_index)
				goto out;
			nr = ((isize - 1) & ~HMFS_PAGE_MASK) + 1;
			if (nr <= offset) {
				goto out;
			}
		}
		nr = nr - offset;
		if (nr > len - copied)
			nr = len - copied;
		hmfs_bug_on(HMFS_I_SB(inode), nr > HMFS_PAGE_SIZE);
		error = get_data_blocks(inode, index, index + 1, xip_mem, 
						&size, RA_END);

		if (unlikely(error || size != 1)) {
			if (error == -ENODATA) {
				/* sparse */
				zero = 1;
			} else
				goto out;
		}

		/* copy to user space */
		if (!zero)
			left = __copy_to_user(buf + copied, xip_mem[0] + offset, nr);
		else
			left = __clear_user(buf + copied, nr);

		if (left) {
			error = -EFAULT;
			goto out;
		}
		copied += (nr - left);
		offset += (nr - left);
		index += offset >> HMFS_PAGE_SIZE_BITS;
		offset &= ~HMFS_PAGE_MASK;
	} while (copied < len);

out:
	*ppos = pos + copied;
	if (filp)
		file_accessed(filp);

	return (copied ? copied : error);
}

#ifdef CONFIG_HMFS_FAST_READ
static inline bool is_fast_read_file(struct ro_file_address *addr_struct)
{
	return addr_struct && (addr_struct->magic == HMFS_SUPER_MAGIC);
}

static struct ro_file_address *new_ro_file_address(void *addr, unsigned int count)
{
	struct ro_file_address *addr_struct;

	addr_struct = kmem_cache_alloc(ro_file_address_cachep, GFP_KERNEL);

	if (addr_struct) {
		addr_struct->magic = HMFS_SUPER_MAGIC;
		addr_struct->start_addr = addr;
		addr_struct->count = count;
	}
	return addr_struct;
}

static void free_ro_file_address(struct file *filp)
{
	kmem_cache_free(ro_file_address_cachep, filp->private_data);
	filp->private_data = NULL;
}

static int remap_file_range(struct inode *inode, struct page **pages, int count)
{
	void **blocks_buf;
	int buf_size = 0;
	/* index of buffer */
	int b_index = 0;
	/* index of file data */
	int f_index = 0;
	int err;
	u64 pfn;
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);

	blocks_buf = kzalloc(HMFS_PAGE_SIZE, GFP_KERNEL);
	if (!blocks_buf)
		return -ENOMEM;

	do {
		if (b_index >= buf_size) {
			buf_size = 0;
			b_index = 0;
			err = get_data_blocks(inode, f_index, count, blocks_buf, &buf_size,
						RA_DB_END);		
			if (!buf_size)
				goto out;
		}
		if (blocks_buf[b_index])
			pfn = pfn_from_vaddr(sbi, blocks_buf[b_index]);
		else
			pfn = sbi->map_zero_page_number;

		pages[f_index] = pfn_to_page(pfn);
		f_index++;
		b_index++;
	} while(f_index < count);

	err = 0;
out:
	kfree(blocks_buf);
	return err;
}

/* 
 * Open file for hmfs, if it's a read-only file, then remap it into 
 * VMALLOC area to accelerate reading
 */
int hmfs_file_open(struct inode *inode, struct file *filp)
{
	int ret;
	unsigned long size;
	struct hmfs_inode_info *fi = HMFS_I(inode);
	void *map_addr;
	struct page **pages;
	int count;

	ret = generic_file_open(inode, filp);
	if (ret || (filp->f_flags & O_ACCMODE) != O_RDONLY ||
				is_inline_inode(inode))
		return ret;;

	if (filp->private_data)
		return 0;

	/* Do not map an empty file */
	size = i_size_read(inode);
	if (!size || fi->read_addr)
		return 0;

	count = align_page_right(size) >> HMFS_PAGE_SIZE_BITS;
	pages = kzalloc(count * sizeof(struct page *), GFP_KERNEL);
	if (!pages)
		return 0;

	ret = remap_file_range(inode, pages, count);

	if (ret) {
		goto free_pages;
	}

	map_addr = vm_map_ram(pages, count, 0, PAGE_KERNEL);
	if (map_addr)
		filp->private_data = new_ro_file_address(map_addr, count);
free_pages:
	kfree(pages);
	return 0;
}

static int hmfs_release_file(struct inode *inode, struct file *filp)
{
	int ret = 0;
	struct hmfs_inode_info *fi = HMFS_I(inode);
	struct ro_file_address *addr_struct = NULL;

	addr_struct = filp->private_data;
	if (is_fast_read_file(addr_struct)) {
		hmfs_bug_on(HMFS_I_SB(inode), (filp->f_flags & O_ACCMODE)
				!= O_RDONLY);

		vm_unmap_ram(addr_struct->start_addr, addr_struct->count);
		/* 
		 * Use the vm area unlocked, assuming the caller unsures there isn't
		 * another iounmap for the same address in parallel. Reuse of the virtual
		 * address is prevented by leaving it in the global lists 
		 * until we're done with it.
		 */
		free_ro_file_address(filp);
	}
	
	if (is_inode_flag_set(fi, FI_DIRTY_INODE))
		ret = sync_hmfs_inode(inode, false);
	else if (is_inode_flag_set(fi, FI_DIRTY_SIZE))
		ret = sync_hmfs_inode_size(inode, false);

	return ret;
}

static ssize_t hmfs_file_fast_read(struct file *filp, char __user *buf,
				size_t len, loff_t *ppos)
{
	loff_t isize = i_size_read(filp->f_inode);
	size_t copied = len;
	unsigned long left;
	struct ro_file_address *addr_struct = filp->private_data;
	int err = 0;

	if (*ppos + len > isize)
		copied = isize - *ppos;

	if (!copied)
		return 0;

	inode_read_unlock(filp->f_inode);
	left = __copy_to_user(buf, addr_struct->start_addr, copied);
	inode_read_lock(filp->f_inode);

	if (left == copied)
		err = -EFAULT;

	*ppos = *ppos + copied;
	return err ? err : copied - left;
}

static ssize_t hmfs_xip_file_read(struct file *filp, char __user *buf,
				size_t len, loff_t *ppos)
{
	int ret = 0;

	inode_read_lock(filp->f_inode);
	if (!i_size_read(filp->f_inode))
		goto out;

	if (likely(!is_fast_read_file((struct ro_file_address *)
						filp->private_data)))
		ret = __hmfs_xip_file_read(filp, buf, len, ppos);
	else
		ret = hmfs_file_fast_read(filp, buf, len, ppos);

out:
	inode_read_unlock(filp->f_inode);
	return ret;
}

int init_ro_file_address_cache(void)
{
	ro_file_address_cachep = hmfs_kmem_cache_create("hmfs_ro_address_cache",
									sizeof(struct ro_file_address), NULL);
	if (!ro_file_address_cachep)
		return -ENOMEM;
	return 0;
}

void destroy_ro_file_address_cache(void)
{
	kmem_cache_destroy(ro_file_address_cachep);
}

#else
/*
 * 读取filp指向文件的内容
 * 若文件长度为0则直接返回
 * 否则调用函数__hmfs_xip_file_read进行读取
 */
static ssize_t hmfs_xip_file_read(struct file *filp, char __user *buf,
				size_t len, loff_t *ppos)
{
	int ret = 0;

	mutex_lock(&filp->f_inode->i_mutex);
	if (!i_size_read(filp->f_inode))
		goto out;

	ret = __hmfs_xip_file_read(filp, buf, len, ppos);

out:
	mutex_unlock(&filp->f_inode->i_mutex);
	return ret;
}
/*直接调用通用的file_open函数*/
int hmfs_file_open(struct inode *inode, struct file *filp)
{
	return generic_file_open(inode, filp);
}
/*
 * 释放文件
 * 并根据文件inode的flag标志判断inode是否为脏
 * 若为脏，将文件内容同步到介质上
 */
static int hmfs_release_file(struct inode *inode, struct file *filp)
{
	int ret = 0;
	struct hmfs_inode_info *fi = HMFS_I(inode);

	if (is_inode_flag_set(fi, FI_DIRTY_INODE))
		ret = sync_hmfs_inode(inode, false);
	else if (is_inode_flag_set(fi, FI_DIRTY_SIZE))
		ret = sync_hmfs_inode_size(inode, false);

	return ret;
}
#endif

/**
 * hmfs_file_llseek - llseek implementation for in-memory files
 * @file:	file structure to seek on
 * @offset:	file offset to seek to
 * @whence:	type of seek
 *
 * This is a generic implemenation of ->llseek useable for all normal local
 * filesystems.  It just updates the file offset to the value specified by
 * @offset and @whence.
 */
/*
 * 重新定位读/写文件的偏移量 file指向目标文件 offset为偏移量 whence指定偏移类型
 * whence为SEEK_END时将新位置指定成从文件结尾开始的的一个偏移距离
 * whence为SEEK_CUR时将新位置指定成从当前文件位置开始的一个偏移距离
 * whence为SEEK_DATA时将新位置指定成下一个大于等于偏移量的非孔文件区域的起始处
 * whence为SEEK_HOLE时将新位置指定成下一个大于等于偏移量的孔区域的起始处
 */

loff_t hmfs_file_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file->f_mapping->host;
	int ret;
	loff_t maxsize = inode->i_sb->s_maxbytes;
	loff_t eof = i_size_read(inode);
	unsigned pg_index, end_blk;

	mutex_lock(&inode->i_mutex);

	/*文件占用的block数*/
	end_blk = (eof + HMFS_PAGE_SIZE - 1) >> HMFS_PAGE_SIZE_BITS;

	switch (whence) {
	case SEEK_END:		
		/* size of the file plus offset [bytes] */
		offset += eof;
		break;
	case SEEK_CUR:
		/* current location plus offset [bytes] */
		spin_lock(&file->f_lock);
		offset = vfs_setpos(file, file->f_pos + offset, maxsize);
		spin_unlock(&file->f_lock);
		ret = offset;
		goto out;
	case SEEK_DATA:	
		/* move to position of data where >= offset */
		if (offset >= eof) {
			ret = -ENXIO;
			goto out;
		}
		if (is_inline_inode(inode)) {
			offset = 0;
			break;
		}
		pg_index = hmfs_file_seek_hole_data(inode, end_blk, offset, SEEK_DATA);
		offset = pg_index << HMFS_PAGE_SIZE_BITS;
		break;
	case SEEK_HOLE:
		/*
		 * There is a virtual hole at the end of the file, so as long as
		 * offset isn't i_size or larger, return i_size.
		 */
		if (offset >= eof) {
			ret = -ENXIO;
			goto out;
		}
		if (is_inline_inode(inode)) {
			offset = eof;
			break;
		}
		pg_index = hmfs_file_seek_hole_data(inode, end_blk, offset, SEEK_HOLE);
		offset = pg_index << HMFS_PAGE_SIZE_BITS;
		break;
	}

	ret = vfs_setpos(file, offset, maxsize);
out:
	mutex_unlock(&inode->i_mutex);
	return ret;
}
/*
 * 对filp指向文件进行写操作
 * buf指向用户写的缓冲区，count为写的长度
 * ppos指向写的位置相对文件的偏移量,pos为偏移量
 * 先进行各类访问、权限等的检查后调用__hmfs_xip_file_write进行写操作
 */
static ssize_t __hmfs_xip_file_write(struct file *filp, const char __user *buf,
				size_t count, loff_t pos, loff_t *ppos)
{
	struct inode *inode = filp->f_inode;
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	long status = 0;
	size_t bytes;
	ssize_t written = 0;
	struct hmfs_inode *inode_block;

	if (is_inline_inode(inode)) {
/*
 * 若写入之后的文件长度大于内嵌文件最大长度
 * 将文件由内嵌文件转化为普通文件
 * 并进行普通文件写
 */
		if (pos + count > HMFS_INLINE_SIZE) {
			status = hmfs_convert_inline_inode(inode);
			if (status) {
				goto out;
			}
			goto normal_write;
		}
/*
 * 否则分配新的inode block
 * 并调用__copy_from_user_nocache将缓冲区内容写到内嵌文件对应位置
 */
		inode_block = alloc_new_node(HMFS_I_SB(inode), inode->i_ino, inode,
							SUM_TYPE_INODE, false);
		if (IS_ERR(inode_block)) {
			status = PTR_ERR(inode_block);
			goto out;
		}
		written = count - __copy_from_user_nocache((__u8 *)inode_block->inline_content 
								+ pos, buf, count);
		if (unlikely(written != count)) {
			status = -EFAULT;
			written = 0;
		} else {
			pos += count;
		}
		goto out;
	}

normal_write:
	do {
		unsigned long index;
		unsigned long offset;
		size_t copied;
		void *xip_mem;

		offset = pos & ~HMFS_PAGE_MASK;
		index = pos >> HMFS_PAGE_SIZE_BITS;
		bytes = HMFS_PAGE_SIZE - offset;
		if (bytes > count)
			bytes = count;
/*
 * 普通文件写
 * 分配新的数据块再调用__copy_from_user_nocache将缓冲区写到数据块对应位置
 * 根据偏移量offset和输入长度count，依次按块写直到全部写完
 */
		xip_mem = alloc_new_data_block(sbi, inode, index);
		if (unlikely(IS_ERR(xip_mem))) {
			status = -ENOSPC;
			break;
		}

		/* To avoid deadlock between fi->i_lock and mm->mmap_sem in mmap */
		inode_write_unlock(inode);
		copied = bytes - __copy_from_user_nocache(xip_mem + offset, 
								buf, bytes);
		inode_write_lock(inode);

		if (likely(copied > 0)) {
			status = copied;

			if (status >= 0) {
				written += status;
				count -= status;
				pos += status;
				buf += status;
			}
		}
		if (unlikely(copied != bytes))
			if (status >= 0)
				status = -EFAULT;
		if (status < 0)
			break;
	} while (count);
out:
	*ppos = pos;

	if (pos > inode->i_size) {
		mark_size_dirty(inode, pos);
	}
	return written ? written : status;
}
/*
 * 对filp指向文件进行写操作
 * buf指向用户写的缓冲区，len为写的长度
 * ppos指向写的位置相对文件的偏移量
 * 先进行各类访问、权限等的检查后调用__hmfs_xip_file_write进行写操作
 */
ssize_t hmfs_xip_file_write(struct file * filp, const char __user * buf,
			    size_t len, loff_t * ppos)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = filp->f_inode;
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	size_t count = 0, ret;
	loff_t pos;
	int ilock;
/*检查缓冲区对应长度的内容是否能访问*/
	if (!access_ok(VERIFY_READ, buf, len)) {
		ret = -EFAULT;
		goto out_up;
	}

	pos = *ppos;
	count = len;

	current->backing_dev_info = mapping->backing_dev_info;
/*
 * 边界检查，需要判断写入数据是否超界、小文件边界检查以及设备是否是read-only。
 * 如果超界，那么降低写入数据长度
 */
	ret = generic_write_checks(filp, &pos, &count, S_ISBLK(inode->i_mode));

	if (ret)
		goto out_backing;
/*count为实际可以写入的数据长度，如果可以写入数据长度为0，直接结束 */
	if (count == 0)
		goto out_backing;

	ret = file_remove_suid(filp);
	if (ret)
		goto out_backing;

	ret = file_update_time(filp);
	if (ret)
		goto out_backing;

	inode->i_ctime = inode->i_mtime = CURRENT_TIME_SEC;

	mark_inode_dirty(inode);

	ilock = mutex_lock_op(sbi);
	inode_write_lock(inode);

	ret = __hmfs_xip_file_write(filp, buf, count, pos, ppos);

	inode_write_unlock(inode);
	mutex_unlock_op(sbi, ilock);

out_backing:
	current->backing_dev_info = NULL;
out_up:
	return ret;
}

/* dn->node_block should be writable */
/*
 * 截断dn指向的direct node中的数据
 * 检查dn->ofs_in_node之后一共count个地址指向的块是否为最新版本，若不是则删除无效块
 * 再将删除后的有效块数量更新到inode和超级块中，并将inode标记为脏
 */
int truncate_data_blocks_range(struct dnode_of_data *dn, int count)
{
	int nr_free = 0, ofs = dn->ofs_in_node;
	struct hmfs_sb_info *sbi = HMFS_I_SB(dn->inode);
	struct hmfs_node *raw_node = (struct hmfs_node *)dn->node_block;
	struct hmfs_node *new_node = NULL;
	block_t addr;
	struct hmfs_summary *node_sum = NULL;
	nid_t nid;
	char sum_type;

	node_sum = get_summary_by_addr(sbi, L_ADDR(sbi, raw_node));
	nid = get_summary_nid(node_sum);
	sum_type = dn->level ? SUM_TYPE_DN : SUM_TYPE_INODE;
	hmfs_bug_on(sbi, sum_type != get_summary_type(node_sum));
	new_node = alloc_new_node(sbi, nid, dn->inode, sum_type, false);

	if (IS_ERR(new_node))
		return PTR_ERR(new_node);

	for (; count > 0; count--, ofs++) {
		if (dn->level)
			addr = raw_node->dn.addr[ofs];
		else
			addr = raw_node->i.i_addr[ofs];

		if (addr == NULL_ADDR)
			continue;

		nr_free += invalidate_delete_block(sbi, le64_to_cpu(addr));

		if (dn->level)
			new_node->dn.addr[ofs] = NULL_ADDR;
		else
			new_node->i.i_addr[ofs] = NULL_ADDR;
	}


	if (nr_free) {
		dec_valid_block_count(sbi, dn->inode, nr_free);
		mark_inode_dirty(dn->inode);
	}

	return nr_free;
}

/*
 * Because we truncate whole direct node, we don't mark the
 * addr in direct node. Instead, we set the address of direct node
 * in its parent indirect node to be NULL_ADDR
 */
/*
 * 截断dn指向的direct node中的数据
 * 检查dn->node_block中的每个地址指向的块是否为最新版本，若不是则删除无效块
 * 再将删除后的有效块数量更新到inode和超级块中，并将inode标记为脏
 */
void truncate_data_blocks(struct dnode_of_data *dn)
{
	struct direct_node *node_block = dn->node_block;
	struct hmfs_sb_info *sbi = HMFS_I_SB(dn->inode);
	int count = ADDRS_PER_BLOCK;
	int nr_free = 0, ofs = 0;
	__le64 *entry = node_block->addr;

	for (; ofs < ADDRS_PER_BLOCK ; ofs++, count--, entry++) {
		if (*entry != NULL_ADDR) {
			nr_free += invalidate_delete_block(sbi, le64_to_cpu(*entry));
		}
	}

	if (nr_free) {
		dec_valid_block_count(sbi, dn->inode, nr_free);
		mark_inode_dirty(dn->inode);
	}
}
/*
 * 将文件某个偏移量from所对应块在from之后的内容清零（只清除该块内容）
 * @inode对应文件
 * @from对应在文件中的偏移量
 */
static void truncate_partial_data_page(struct inode *inode, block_t from)
{
	unsigned offset = from & (HMFS_PAGE_SIZE - 1);

	if (!offset)
		return;
	alloc_new_data_partial_block(inode, from >> HMFS_PAGE_SIZE_BITS, offset,
			HMFS_PAGE_SIZE, true);
	return;
}
/*
 * 清除普通文件某个偏移量之后的全部内容
 * @inode对应文件
 * @from对应偏移量
 */
static int __truncate_blocks(struct inode *inode, block_t from)
{
	struct dnode_of_data dn;
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	int count, err;
	block_t free_from;

	free_from = (from + HMFS_PAGE_SIZE - 1) >> HMFS_PAGE_SIZE_BITS;

	set_new_dnode(&dn, inode, NULL, NULL, 0);
	err = get_dnode_of_data(&dn, free_from, LOOKUP_NODE);

	if (err) {
		goto free_next;
	}
	if (!dn.level)
		count = NORMAL_ADDRS_PER_INODE;
	else
		count = ADDRS_PER_BLOCK;

	count -= dn.ofs_in_node;
	hmfs_bug_on(sbi, count < 0);

	if (dn.ofs_in_node || !dn.level) {
		truncate_data_blocks_range(&dn, count);
		free_from += count;
	}

free_next:
/*
 * 先调用truncate_inode_blocks删除偏移量之后的所有块内容
 * 再调用truncate_partial_data_page删除偏移量所在的块在其之后的内容
 */
	err = truncate_inode_blocks(inode, free_from);
	truncate_partial_data_page(inode, from);

	return err;
}
/*
 * 清除文件某个偏移量之后的全部内容
 * @inode对应文件
 * @from对应偏移量
 * 若为内嵌型文件直接在本函数处理
 * 否则调用__truncate_blocks处理普通文件
 */
static int truncate_blocks(struct inode *inode, block_t from)
{
	struct hmfs_inode *inode_block;

	if (is_inline_inode(inode)) {
		inode_block = alloc_new_node(HMFS_I_SB(inode), inode->i_ino,
							inode, SUM_TYPE_INODE, false);
		if (IS_ERR(inode_block))
			return PTR_ERR(inode_block);
		memset_nt((__u8 *)inode_block->inline_content, 0,
				HMFS_INLINE_SIZE - from);
		return 0;
	}

	return __truncate_blocks(inode, from);
}
/*
 * 清除@inode对应文件在i_size之后的内容
 * 再修改i_mtime及i_ctime并将inode标记为脏
 */
void hmfs_truncate(struct inode *inode)
{
	if (!(S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode)
			|| S_ISLNK(inode->i_mode)))
		return;

	if (!truncate_blocks(inode, i_size_read(inode))) {
		inode->i_mtime = inode->i_ctime = CURRENT_TIME;
		mark_inode_dirty(inode);
	}

}
/*
 *截断孔
 *在inode指向文件的第start块与第end块之间截断出孔区域
 *用于对可能占用多块的普通文件预分配空间
 */
int truncate_hole(struct inode *inode, pgoff_t start, pgoff_t end)
{
	pgoff_t index;
	int err;
	struct dnode_of_data dn;

	for (index = start; index < end; index++) {
		set_new_dnode(&dn, inode, NULL, NULL, 0);
		err = get_dnode_of_data(&dn, index, LOOKUP_NODE);
		if (err) {
			if (err == -ENODATA)
				continue;
			return err;
		}
		truncate_data_blocks_range(&dn, 1);
	}
	return 0;
}
/*
 * 填充零，即在inode指向文件第index个块偏移量为start处
 * 填充一长度为len的孔区域
 */
static void fill_zero(struct inode *inode, pgoff_t index, loff_t start,
		      loff_t len)
{
	if (!len)
		return;

	alloc_new_data_partial_block(inode, index, start, start + len, true);
}
/*
 * 打孔，对于inode指向文件在offset偏移量处增加一长度为len的孔
 * 用于fallocate函数预分配空间
 */
static int punch_hole(struct inode *inode, loff_t offset, loff_t len, int mode)
{
	pgoff_t pg_start, pg_end;
	loff_t off_start, off_end;
	loff_t blk_start, blk_end;
	int ret = 0;

	pg_start = ((unsigned long long) offset) >> HMFS_PAGE_SIZE_BITS;
	pg_end = ((unsigned long long) offset + len) >> HMFS_PAGE_SIZE_BITS;
	off_start = offset & (HMFS_PAGE_SIZE - 1);
	off_end = (offset + len) & (HMFS_PAGE_SIZE - 1);
/*
 * 若为inode内嵌文件，且增加孔后长度仍符合内嵌文件，则不需打孔
 *（因inode内嵌文件创建时内容已经初始化为0）
 * 否则若增加孔后长度大于内嵌文件限制，则转化文件类型为普通文件再打孔
 */
	if (is_inline_inode(inode)) {
		if (offset + len > HMFS_INLINE_SIZE) {
			ret = hmfs_convert_inline_inode(inode);
			if (ret)
				return ret;
			goto punch;
		}
		/* 
		 * We don't need to memset 0 of inode->inline_content. Because 
		 * it has been initialized when creating
		 */
		goto out;
	}

punch:
	if (pg_start == pg_end) {
		fill_zero(inode, pg_start, off_start, off_end - off_start);
	} else {
		if (off_start)
			fill_zero(inode, pg_start++, off_start,
				  HMFS_PAGE_SIZE - off_start);
		if (off_end)
			fill_zero(inode, pg_end, 0, off_end);

		if (pg_start < pg_end) {
			blk_start = pg_start << HMFS_PAGE_SIZE_BITS;
			blk_end = pg_end << HMFS_PAGE_SIZE_BITS;

			ret = truncate_hole(inode, pg_start, pg_end);
		}
	}

out:
	if (!(mode & FALLOC_FL_KEEP_SIZE)
	    && i_size_read(inode) <= (offset + len)) {
		mark_size_dirty(inode, offset + len);
	}

	return ret;
}

static int expand_inode_data(struct inode *inode, loff_t offset, loff_t len,
			     int mode)
{
	pgoff_t index, pg_start, pg_end;
	loff_t new_size = i_size_read(inode);
	loff_t off_start, off_end;
	struct dnode_of_data dn;
	int ret;

	ret = inode_newsize_ok(inode, (len + offset));
	if (ret)
		return ret;

	pg_start = ((unsigned long long) offset) >> HMFS_PAGE_SIZE_BITS;
	pg_end = ((unsigned long long) offset + len) >> HMFS_PAGE_SIZE_BITS;

	off_start = offset & (HMFS_PAGE_SIZE - 1);
	off_end = (offset + len) & (HMFS_PAGE_SIZE - 1);

	if (is_inline_inode(inode)) {
		if (offset + len > HMFS_INLINE_SIZE) {
			ret = hmfs_convert_inline_inode(inode);
			if (ret)
				return ret;
			goto expand;
		}
		/* If it's inline inode, we don;t need to memset 0 */
		goto out;
	}

expand:
	for (index = pg_start; index <= pg_end; index++) {
		set_new_dnode(&dn, inode, NULL, NULL, 0);

		ret = get_dnode_of_data(&dn, index, ALLOC_NODE);
		if (ret) {
			break;
		}

		if (pg_start == pg_end)
			new_size = offset + len;
		else if (index == pg_start && off_start)
			new_size = (index + 1) << HMFS_PAGE_SIZE_BITS;
		else if (index == pg_end)
			new_size = (index << HMFS_PAGE_SIZE_BITS) + off_end;
		else
			new_size += HMFS_PAGE_SIZE;
	}

out:
	if (!(mode & FALLOC_FL_KEEP_SIZE) && i_size_read(inode) < new_size) {
		mark_size_dirty(inode, new_size);
	}

	return ret;
}

static int hmfs_get_mmap_block(struct inode *inode, pgoff_t index, 
				unsigned long *pfn, int vm_type)
{
	int err;
	void *data_block[1];
	int nr_blk;
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	block_t data_block_addr;

	if (vm_type & VM_WRITE) {
		data_block[0] = alloc_new_data_block(sbi, inode, index);
		if (IS_ERR(data_block[0]))
			return PTR_ERR(data_block[0]);
	} else {
		hmfs_bug_on(sbi, !(vm_type & VM_READ));
		err = get_data_blocks(inode, index, index + 1, data_block,
					&nr_blk, RA_DB_END);

		if (nr_blk < 1)
			return err;

		/* A hole in file */
		if (!data_block[0]) {
			*pfn = sbi->map_zero_page_number;
			goto out;
		}
	}
	data_block_addr = L_ADDR(sbi, data_block[0]);
	*pfn = (sbi->phys_addr + data_block_addr) >> PAGE_SHIFT;
out:
	return 0;
}

static void hmfs_filemap_close(struct vm_area_struct *vma)
{
	struct address_space *mapping = vma->vm_file->f_mapping;
	struct inode *inode = mapping->host;
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	unsigned long pg_start, pg_end;
	unsigned long vm_start, vm_end;

	vm_start = vma->vm_start & PAGE_MASK;
	vm_end = vma->vm_end & PAGE_MASK;
	if (vm_end < vm_start)
		return;
	pg_start = vma->vm_pgoff;
	pg_end = ((vm_end - vm_start) >> PAGE_SHIFT) + pg_start;


	while (pg_start <= pg_end) {
		remove_mmap_block(sbi, vma->vm_mm, pg_start);
		pg_start++;
	}
}

int add_mmap_block(struct hmfs_sb_info *sbi, struct mm_struct *mm,
				unsigned long vaddr, unsigned long pgoff)
{
	struct hmfs_mmap_block *entry;

	entry = kmem_cache_alloc(mmap_block_slab, GFP_ATOMIC);
	if (!entry) {
		return -ENOMEM;
	}

	entry->mm = mm;
	entry->vaddr = vaddr;
	entry->pgoff = pgoff;
	INIT_LIST_HEAD(&entry->list);
	/* No check for duplicate */
	lock_mmap(sbi);
	list_add_tail(&entry->list, &sbi->mmap_block_list);
	unlock_mmap(sbi);
	return 0;
}

int remove_mmap_block(struct hmfs_sb_info *sbi, struct mm_struct *mm,
				unsigned long pgoff)
{
	struct hmfs_mmap_block *entry;
	struct list_head *head, *this, *next;
	
	head = &sbi->mmap_block_list;
	lock_mmap(sbi);
	list_for_each_safe(this, next, head) {
		entry = list_entry(this, struct hmfs_mmap_block, list);
		if (entry->mm == mm && entry->pgoff == pgoff) {
			list_del(&entry->list);
			kmem_cache_free(mmap_block_slab, entry);
		}
	}
	unlock_mmap(sbi);
	return 0;
}

int migrate_mmap_block(struct hmfs_sb_info *sbi)
{
	struct hmfs_mmap_block *entry;
	struct list_head *head, *this, *next;
	pte_t *pte;
	spinlock_t *ptl;

	head = &sbi->mmap_block_list;
	lock_mmap(sbi);
	list_for_each_safe(this, next, head) {
		entry = list_entry(this, struct hmfs_mmap_block, list);

		__cond_lock(ptl, pte = (*hmfs_get_locked_pte) (entry->mm, entry->vaddr,
									&ptl));

		if (!pte)
			goto free;
		if (pte_none(*pte))
			goto next;
		pte->pte = 0;
next:
		pte_unmap_unlock(pte, ptl);
free:
		list_del(&entry->list);
	}
	unlock_mmap(sbi);
	return 0;
}

static int hmfs_filemap_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct address_space *mapping = vma->vm_file->f_mapping;
	struct inode *inode = mapping->host;
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	pgoff_t offset = vmf->pgoff, size;
	unsigned long pfn = 0;
	int err = 0;

	size = (i_size_read(inode) + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;
	if (offset >= size)
		return VM_FAULT_SIGBUS;

	inode_write_lock(inode);
	err = hmfs_get_mmap_block(inode, offset, &pfn, vma->vm_flags);
	inode_write_unlock(inode);
	if (unlikely(err))
		return VM_FAULT_SIGBUS;

	err = add_mmap_block(sbi, vma->vm_mm, (unsigned long)vmf->virtual_address,
				vmf->pgoff);
	if (err)
		return VM_FAULT_SIGBUS;

	err = vm_insert_mixed(vma, (unsigned long)vmf->virtual_address, pfn);

	if (err == -ENOMEM)
		return VM_FAULT_SIGBUS;

	if (err != -EBUSY)
		hmfs_bug_on(HMFS_I_SB(inode), err);

	return VM_FAULT_NOPAGE;
}

static const struct vm_operations_struct hmfs_file_vm_ops = {
	.close = hmfs_filemap_close,
	.fault = hmfs_filemap_fault,
};
/*
 * 文件映射，将file指向文件映射到vma指向的地址空间
 * 修改文件访问信息
 * 设置vma的flag标志并将其操作指针指向hmfs_file_vm_ops
 */
static int hmfs_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	file_accessed(file);
	vma->vm_flags |= VM_MIXEDMAP;
	vma->vm_ops = &hmfs_file_vm_ops;
	return 0;
}
/*
 * 根据file指针同步文件
 * 若为只读文件不能同步直接返回
 * 否则根据inode状态是为FI_DIRTY_INODE还是FI_DIRTY_SIZE
 * 分别选择对应函数同步inode信息
 */
int hmfs_sync_file(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct inode *inode = file->f_mapping->host;
	struct hmfs_inode_info *fi = HMFS_I(inode);
	int ret = 0, ilock;
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);

	if (hmfs_readonly(inode->i_sb))
		return 0;

	ilock = mutex_lock_op(sbi);
	inode_write_lock(inode);

	/* We don't need to sync data pages */
	if (is_inode_flag_set(fi, FI_DIRTY_INODE))
		ret = sync_hmfs_inode(inode, false);
	else if (is_inode_flag_set(fi, FI_DIRTY_SIZE))
		ret = sync_hmfs_inode_size(inode, false);

	inode_write_unlock(inode);
	mutex_unlock_op(sbi, ilock);

	return ret;
}

/* Pre-allocate space for file from offset to offset + len */
static long hmfs_fallocate(struct file *file, int mode, loff_t offset,
			   loff_t len)
{
	struct inode *inode = file_inode(file);
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	long ret = 0;
	int ilock;

	if (mode & ~(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE))
		return -EOPNOTSUPP;

	if (S_ISDIR(inode->i_mode))
		return -ENODEV;

	ilock = mutex_lock_op(sbi);
	inode_write_lock(inode);
	if (mode & FALLOC_FL_PUNCH_HOLE)
		ret = punch_hole(inode, offset, len, mode);
	else
		ret = expand_inode_data(inode, offset, len, mode);
	inode_write_unlock(inode);
	mutex_unlock_op(sbi, ilock);

	if (!ret) {
		inode->i_mtime = inode->i_ctime = CURRENT_TIME;
		mark_inode_dirty(inode);
	}

	return ret;
}

#define HMFS_REG_FLMASK		(~(FS_DIRSYNC_FL | FS_TOPDIR_FL))
#define HMFS_OTHER_FLMASK	(FS_NODUMP_FL | FS_NOATIME_FL)
/*
 * 对于@flags进行掩码处理
 * @mode对应目录文件时直接返回falgs
 * @mode对应普通文件时返回flags & HMFS_REG_FLMASK
 * 其他情况时返回flags & HMFS_OTHER_FLMASK
 */
static inline __u32 hmfs_mask_flags(umode_t mode, __u32 flags)
{
	if (S_ISDIR(mode))
		return flags;
	else if (S_ISREG(mode))
		return flags & HMFS_REG_FLMASK;
	else 
		return flags & HMFS_OTHER_FLMASK;
}
/*
 * 向设备发送或接收控制信息
 * @filp指向设备文件标识符
 * @arg指向用户空间目标地址
 * @cmd为HMFS_IOC_GETFLAGS时，将i_flags中用户可见位发送到用户空间目标地址
 * @cmd为HMFS_IOC_SETFLAGS时，将用户空间目标地址的值复制到flags中
 * @cmd为HMFS_IOC_GETVERSION时，将i_generation发送到用户空间目标地址
 * 若不符合以上任何一种情况则返回-ENOTTY
 */
long hmfs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct hmfs_inode_info *fi = HMFS_I(inode);
	unsigned int flags, oldflags;
	int ret;

	switch (cmd) {
	case HMFS_IOC_GETFLAGS:
		flags = fi->i_flags & FS_FL_USER_VISIBLE;
		return put_user(flags, (int __user *) arg);
	case HMFS_IOC_SETFLAGS:
		ret = mnt_want_write_file(filp);
		if (ret)
			return ret;

		if (!inode_owner_or_capable(inode)) {
			ret = -EACCES;
			goto out;
		}

		if (get_user(flags, (int __user *) arg)) {
			ret = -EFAULT;
			goto out;
		}

		flags = hmfs_mask_flags(inode->i_mode, flags);

		mutex_lock(&inode->i_mutex);

		oldflags = fi->i_flags;

		if ((flags ^ oldflags) & (FS_APPEND_FL | FS_IMMUTABLE_FL)) {
			if (!capable(CAP_LINUX_IMMUTABLE)) {
				mutex_unlock(&inode->i_mutex);
				ret = -EPERM;
				goto out;
			}
		}

		flags = flags & FS_FL_USER_MODIFIABLE;
		flags|= oldflags & ~FS_FL_USER_MODIFIABLE;
		fi->i_flags = flags;
		mutex_unlock(&inode->i_mutex);
		hmfs_set_inode_flags(inode);
		inode->i_ctime = CURRENT_TIME;
		mark_inode_dirty(inode);
out:
		mnt_drop_write_file(filp);
		return ret;
	case HMFS_IOC_GETVERSION:
		return put_user(inode->i_generation, (int __user *)arg);
	default:
		return -ENOTTY;
	}
}

#ifdef CONFIG_COMPAT
/*
 * hmfs_ioctl函数的兼容性包装函数
 * 向设备发送或接收控制信息
 * @filp指向设备文件标识符
 * @arg指向用户空间目标地址
 * 调整@cmd的值再调用hmfs_ioctl发送或接收控制信息
 */
long hmfs_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case HMFS_IOC32_GETFLAGS:
		cmd = HMFS_IOC_GETFLAGS;
		break;
	case HMFS_IOC32_SETFLAGS:
		cmd = HMFS_IOC_SETFLAGS;
		break;
	case HMFS_IOC32_GETVERSION:
		cmd = HMFS_IOC_GETVERSION;
		break;
	default:
		return -ENOIOCTLCMD;
	}

	return hmfs_ioctl(file, cmd, (unsigned long) compat_ptr(arg));
}
#endif

const struct file_operations hmfs_file_operations = {
	.llseek = hmfs_file_llseek,
	.read = hmfs_xip_file_read,
	.write = hmfs_xip_file_write,
	//.aio_read       = xip_file_aio_read,
	//.aio_write      = xip_file_aio_write,
	.open = hmfs_file_open,
	.release = hmfs_release_file,
	.mmap = hmfs_file_mmap,
	.fsync = hmfs_sync_file,
	.fallocate = hmfs_fallocate,
	.unlocked_ioctl = hmfs_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = hmfs_compat_ioctl,
#endif
};

const struct inode_operations hmfs_file_inode_operations = {
	.getattr = hmfs_getattr,
	.setattr = hmfs_setattr,
#ifdef CONFIG_HMFS_XATTR
	.setxattr = generic_setxattr,
	.getxattr = generic_getxattr,
	.listxattr = hmfs_listxattr,
	.removexattr = generic_removexattr,
#endif 
};
/*
 * 创建slab高速缓存，使mmap_block_slab指向缓存
 * 成功返回0，失败返回-ENOMEM
 */
int create_mmap_struct_cache(void)
{
	mmap_block_slab = hmfs_kmem_cache_create("hmfs_mmap_block",
							sizeof(struct hmfs_mmap_block), NULL);
	if (!mmap_block_slab)
		return -ENOMEM;
	return 0;
}
/*
 * 销毁mmap_block_slab指向的slab高速缓存
 */
void destroy_mmap_struct_cache(void)
{
	kmem_cache_destroy(mmap_block_slab);
}
