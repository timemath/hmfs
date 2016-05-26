/*
 * fs/hmfs/xattr.c
 *
 * Copyright SJTU RADLAB.
 *             http://radlab.sjtu.edu.cn/
 *
 * Portions of this code from fs/ext2/xattr.c
 * 							  fs/f2fs/xattr.c
 *
 * Copyright (C) 2001-2003 Andreas Gruenbacher <agruen@suse.de>
 *
 * Fix by Harrison Xing <harrison@mountainviewdata.com>.
 * Extended attributes for symlinks and special files added per
 *  suggestion of Luka Renko <luka.renko@hermes.si>.
 * xattr consolidation Copyright (c) 2004 James Morris <jmorris@redhat.com>,
 *  Red Hat Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/dcache.h>
#include <linux/security.h>
#include "xattr.h"
#include "hmfs.h"
#include "hmfs_fs.h"

static const struct xattr_handler *hmfs_xattr_handler_map[];
/**
 * 寻找存储扩展属性的结构体hmfs_xattr_entry
 * @param[in] base_addr 表示遍历的起始地址
 * @param[in] index 表示要寻找的结构体的e_name_index
 * @param[in] name_len 表示要寻找的属性的名称长度
 * @param[in] name 表示要寻找的属性的名称
 * @return 返回值为找到的该属性的hmfs_xattr_entry结构体
 */
static struct hmfs_xattr_entry *__find_xattr(void *base_addr, int index,
				size_t name_len, const char *name)
{
	struct hmfs_xattr_entry *entry;
	
	list_for_each_xattr(entry, base_addr) {
		if (entry->e_name_index != index)
			continue;
		if (entry->e_name_len != name_len)
			continue;
		if (!memcmp(entry->e_name, name, name_len))
			break;
	}

	return entry;
}
/**
 * 得到存储文件扩展属性的块在DRAM中的地址
 * @param[in] inode 指向该文件
 * @return 正常时返回其地址，否则返回NULL
 */
static void *get_xattr_block(struct inode *inode)
{
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	block_t xattr_addr;
	struct hmfs_inode *inode_block;

	inode_block = get_node(sbi, inode->i_ino);
	if (IS_ERR(inode_block))
		return NULL;

	xattr_addr = le64_to_cpu(inode_block->i_xattr_addr);
	if (xattr_addr)
		return ADDR(sbi, xattr_addr);
	return NULL;
}
/**
 * 将扩展属性句柄的prefix字符串，以及参数中的name字符串复制到list中
 * @param[in] dentry 用于索引超级块
 * @param[in] list 用于存储字符串
 * @param[in] list_size 为list存储的最大空间
 * @param[in] name 为拷贝到prefix之后的字符串
 * @param[in] len 为将name拷贝到prefix之后的字符串的长度
 * @param[in] flag 对应扩展属性句柄的种类
 * @return 返回复制的字符串长度
 */
static size_t hmfs_xattr_generic_list(struct dentry *dentry, char *list,
				size_t list_size, const char *name, size_t len, int flags)
{
	struct hmfs_sb_info *sbi = HMFS_SB(dentry->d_sb);
	int total_len, prefix_len;
	const struct xattr_handler *handler;

	switch (flags) {
	case HMFS_XATTR_INDEX_USER:
		if (!test_opt(sbi, XATTR_USER))
			return -EOPNOTSUPP;
		break;
	case HMFS_XATTR_INDEX_TRUSTED:
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		break;
	case HMFS_XATTR_INDEX_SECURITY:
		break;
	default:
		return -EINVAL;
	}

	handler = hmfs_xattr_handler_map[flags];
	prefix_len = strlen(handler->prefix);
	total_len = prefix_len + len + 1;
	if (list && total_len <= list_size) {
		memcpy(list, handler->prefix, prefix_len);
		memcpy(list + prefix_len, name, len);
		list[prefix_len + len] = '\0';
	}
	return total_len;
}
/**
 * 得到扩展属性的属性值
 * @param[in] inode 为要获取扩展属性值得文件inode
 * @param[in] index 为要获取的扩展属性的e_name_index
 * @param[in] name 为要获取的扩展属性的名称
 * @param[in] buffer 为将属性值复制到的目标地址
 * @param[in] buffer_size 为目标缓冲区最大长度
 * @return 返回值为属性值的字符长度或错误信息
 */
static int __hmfs_getxattr(struct inode *inode, int index, const char *name,
				void *buffer, size_t buffer_size) 
{
	struct hmfs_xattr_entry *entry;
	void *xattr_block;
	int error = 0;
	size_t value_len, name_len;

	if (name == NULL)
		return -EINVAL;

	name_len = strlen(name);
	if (name_len > HMFS_NAME_LEN)
		return -ERANGE;
	
	xattr_block = get_xattr_block(inode);
	if (!xattr_block) {
		return -ENODATA;
	}

	entry = __find_xattr(xattr_block, index, name_len, name);
	if (IS_XATTR_LAST_ENTRY(entry)) {
		error = -ENODATA;
		goto out;
	}

	value_len = entry->e_value_len;

	if (buffer && value_len > buffer_size) {
		error = -ERANGE;
		goto out;
	}

	if (buffer) {
		memcpy(buffer, entry->e_name + name_len, value_len);
	}

	error = value_len;
out:
	return error;
} 
/**
 * 获取文件扩展属性的属性值的包装函数
 * 调用__hmfs_getxattr函数进行读取
 * @param[in] inode 为要获取扩展属性值得文件inode
 * @param[in] index 为要获取的扩展属性的e_name_index
 * @param[in] name 为要获取的扩展属性的名称
 * @param[in] buffer 为将属性值复制到的目标地址
 * @param[in] buffer_size 为目标缓冲区最大长度
 * @return 返回值为属性值的字符长度或错误信息
 */
int hmfs_getxattr(struct inode *inode, int index, const char *name,
				void *buffer, size_t buffer_size) 
{
	int ret;

	inode_read_lock(inode);
	ret = __hmfs_getxattr(inode, index, name, buffer, buffer_size);
	inode_read_unlock(inode);
	return ret;
}
/**
 * 获取文件扩展属性
 * 调用函数hmfs_getxattr进行读取
 * @param[in] dentry 为要获取扩展属性值得文件目录项
 * @param[in] flags 为要获取的扩展属性的e_name_index
 * @param[in] name 为要获取的扩展属性的名称
 * @param[in] buffer 为将属性值复制到的目标地址
 * @param[in] size 为目标缓冲区最大长度
 * @return 返回值为属性值的字符长度或错误信息
 */
static int hmfs_xattr_generic_get(struct dentry *dentry, const char *name,
				void *buffer, size_t size, int flags)
{
	struct hmfs_sb_info *sbi = HMFS_SB(dentry->d_sb);

	switch (flags) {
	case HMFS_XATTR_INDEX_USER:
		if (!test_opt(sbi, XATTR_USER))
			return -EOPNOTSUPP;
		break;
	case HMFS_XATTR_INDEX_TRUSTED:
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		break;
	case HMFS_XATTR_INDEX_SECURITY:
		break;
	default:
		return -EINVAL;
	}
	if (strcmp(name, "") == 0)
		return -EINVAL;
	return hmfs_getxattr(dentry->d_inode, flags, name,
					buffer, size);
}
/**
 * 使base_addr指向的hmfs_xattr_header结构体的h_magic值等于HMFS_X_BLOCK_TAG_XATTR
 */
static void init_xattr_block(void *base_addr)
{
	XATTR_HDR(base_addr)->h_magic = cpu_to_le16(HMFS_X_BLOCK_TAG_XATTR);
}
/**
 * 设置文件扩展属性值
 * @param[in] inode 为要设置的文件inode
 * @param[in] index 为要设置的扩展属性的e_name_index
 * @param[in] name 为要设置的属性名
 * @param[in] value 为要设置为的属性值
 * @param[in] size 为该属性值的字符长度
 * @param[in] flags 为XATTR_CREATE时为创建新属性
 * @param[in] flags 为XATTR_REPLACE时为替代已有属性
 * @return 返回值为错误信息
 */
static int __hmfs_setxattr(struct inode *inode, int index,
				const char *name, const void *value, size_t size,
				int flags)
{
	struct hmfs_xattr_entry *this, *last, *next;
	void *base_addr, *new_xattr_blk;
	int newsize, cpy_size;
	size_t name_len;
	int error = -ENOMEM;

	if (name == NULL)
		return -EINVAL;

	if (value == NULL)
		size = 0;

	name_len = strlen(name);

	if (name_len > HMFS_NAME_LEN)
		return -ERANGE;

	if (name_len + size > HMFS_XATTR_VALUE_LEN)
		return -E2BIG;

	base_addr = get_xattr_block(inode);
	if (!base_addr) {
		error = -ENODATA;
		goto out;
	}

	if (!base_addr) {
		if (flags & XATTR_CREATE)
			goto create;
		error = -ENODATA;
		goto out;
	}
	this = __find_xattr(base_addr, index, name_len, name);

	if (this->e_name_index == HMFS_XATTR_INDEX_END &&
				(flags & XATTR_REPLACE)) {
		error = -ENODATA;
		goto out;
	} else if ((flags & XATTR_CREATE) && this->e_name_index !=
						HMFS_XATTR_INDEX_END) {
		error = -EEXIST;
		goto out;
	}
	
	newsize = XATTR_RAW_SIZE + name_len + size;

	/* Check Space */
	if (value) {
		/* If value is NULL, it's a remove operation */
		/* Add another hmfs_xattr_entry for end entry */
		last = XATTR_ENTRY(JUMP(this, newsize + XATTR_RAW_SIZE));

		if (DISTANCE(base_addr, last) > HMFS_XATTR_BLOCK_SIZE) {
			error = -ENOSPC;
			goto out;
		}
	}

create:	
	/* Allocate new xattr block */
	new_xattr_blk = alloc_new_x_block(inode, HMFS_X_BLOCK_TAG_XATTR, false);
	init_xattr_block(new_xattr_blk);	

	/* Remove old entry in old xattr block */
	if (base_addr) {
		/* Copy first part */
		next = XATTR_FIRST_ENTRY(base_addr);
		cpy_size = DISTANCE(next, this);
		hmfs_memcpy(XATTR_FIRST_ENTRY(new_xattr_blk), next, cpy_size);

		/* Get last xattr in source xattr block */
		last = this;
		while (!IS_XATTR_LAST_ENTRY(last))
			last = XATTR_NEXT_ENTRY(last);

		/* Copy second part */
		next = XATTR_NEXT_ENTRY(this);
		cpy_size = DISTANCE(next, last);
		next = XATTR_ENTRY(JUMP(new_xattr_blk, DISTANCE(base_addr, this)));
		hmfs_memcpy(next, XATTR_NEXT_ENTRY(this), cpy_size);
		next = XATTR_ENTRY(JUMP(next, cpy_size));
	} else {
		next = XATTR_FIRST_ENTRY(new_xattr_blk);
	}

	/* Write new entry */
	if (value) {
		next->e_name_index = index;
		next->e_name_len = name_len;
		next->e_value_len = size;
		memcpy(next->e_name, name, name_len);
		memcpy(next->e_name + name_len, value, size);
		next = XATTR_ENTRY(next->e_name + name_len + size);
	}

	/* Write End entry */
	next->e_name_index = HMFS_XATTR_INDEX_END;
	hmfs_bug_on(HMFS_I_SB(inode), DISTANCE(new_xattr_blk, 
			JUMP(next, XATTR_RAW_SIZE)) > HMFS_XATTR_BLOCK_SIZE);

	inode->i_ctime = CURRENT_TIME;
	mark_inode_dirty(inode);
out:
	return error;
}
/**
 * 设置文件扩展属性值的包装函数
 * 调用__hmfs_setxattr设置属性
 * @param[in] inode 为要设置的文件inode
 * @param[in] index 为要设置的扩展属性的e_name_index
 * @param[in] name 为要设置的属性名
 * @param[in] value 为要设置为的属性值
 * @param[in] size 为该属性值的字符长度
 * @param[in] flags 为XATTR_CREATE时为创建新属性，为XATTR_REPLACE时为替代已有属性
 * @return 返回值为错误信息
 */
static int hmfs_setxattr(struct inode *inode, int index, const char *name,
				const void *value, size_t size, int flags)
{
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	int err, ilock;

	ilock = mutex_lock_op(sbi);
	inode_write_lock(inode);
	err = __hmfs_setxattr(inode, index, name, value, size, flags);
	inode_write_unlock(inode);
	mutex_unlock_op(sbi, ilock);

	return err;
}
/**
 * 设置文件扩展属性值的包装函数
 * 调用函数hmfs_setxattr设置属性
 * @param[in] dentry 为要设置的文件目录项
 * @param[in] handler_flags 为要设置的扩展属性的e_name_index
 * @param[in] name 为要设置的属性名
 * @param[in] value 为要设置为的属性值
 * @param[in] size 为该属性值的字符长度
 * @param[in] flags 为XATTR_CREATE时为创建新属性，为XATTR_REPLACE时为替代已有属性
 * @return 返回值为错误信息
 */
static int hmfs_xattr_generic_set(struct dentry *dentry, const char *name,
				const void *value, size_t size, int flags, int handler_flags)
{
	struct hmfs_sb_info *sbi = HMFS_SB(dentry->d_sb);

	switch (handler_flags) {
	case HMFS_XATTR_INDEX_USER:
		if (!test_opt(sbi, XATTR_USER))
			return -EOPNOTSUPP;
		break;
	case HMFS_XATTR_INDEX_TRUSTED:
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		break;
	case HMFS_XATTR_INDEX_SECURITY:
		break;
	default:
		return -EINVAL;
	}
	if (strcmp(name, "") == 0)
		return -EINVAL;
	return hmfs_setxattr(dentry->d_inode, handler_flags, name,
					value, size, flags);
}
/**
 * 将list字符串值设置为系统建议值
 * @param[in] list 为字符串起始地址
 * @param[in] list_size 为list存储的最大长度
 * 其他参数无意义
 * @return 返回设置后的list字符串长度
 */
static size_t hmfs_xattr_advise_list(struct dentry *dentry, char *list,
				size_t list_size, const char *name, size_t len, int flags)
{
	const char *xname = HMFS_SYSTEM_ADVISE_PREFIX;
	size_t size;
	size = strlen(xname) + 1;
	if (list && size <= list_size)
		memcpy(list, xname, size);
	return size;
}
/**
 * 获取文件扩展属性建议值
 * @param[in] dentry 为该文件目录项
 * @param[in] name 为扩展属性名
 * @param[out] buffer 被设置为指向文件i_advise值的地址
 * @return char型数据长度
 */
static int hmfs_xattr_advise_get(struct dentry *dentry, const char *name,
				void *buffer, size_t size, int flags)
{
	struct inode *inode = dentry->d_inode;

	if (strcmp(name ,"") != 0)
		return -EINVAL;

	inode_read_lock(inode);
	if (buffer)
		*((char *)buffer) = HMFS_I(inode)->i_advise;
	inode_read_unlock(inode);
	return sizeof(char);
}
/**
 * 设置文件扩展属性建议值
 * @param[in] dentry 为该文件目录项
 * @param[in] name 为扩展属性名
 * @param[in] value 指向要设置的属性建议值
 * 其他参数无意义
 * @return 成功时返回0，否则返回错误信息
 */
static int hmfs_xattr_advise_set(struct dentry *dentry, const char *name,
				const void *value, size_t size, int flags, int handler_flag)
{
	struct inode *inode = dentry->d_inode;

	if (strcmp(name, "") != 0)
		return -EINVAL;
	if (!inode_owner_or_capable(inode))
		return -EPERM;
	if (value == NULL)
		return -EINVAL;

	inode_write_lock(inode);
	HMFS_I(inode)->i_advise = *(char *)value;
	inode_write_unlock(inode);
	mark_inode_dirty(inode);
	return 0;
}
/**
 * 初始化文件扩展属性 
 * @param[in] inode 为该文件inode
 * @param[in] xattr_array 为要设置的扩展属性初始值的结构体数组初始地址
 * @param[in] page 无意义
 * @return 成功时返回0，否则返回错误信息
 */
static int hmfs_initxattrs(struct inode *inode, const struct xattr *xattr_array,
				void *page)
{
	const struct xattr *xattr;
	int err = 0;

	for (xattr = xattr_array; xattr->name != NULL; xattr++) {
		err = hmfs_setxattr(inode, HMFS_XATTR_INDEX_SECURITY,
					xattr->name, xattr->value, xattr->value_len, 0);
		if (err < 0)
			break;
	}
	return err;
}
/**
 * 安全模式初始化扩展属性
 * 调用内核函数security_inode_init_security完成
 */
int hmfs_init_security(struct inode *inode ,struct inode *dir,
				const struct qstr *qstr, struct page *ipage)
{
	return security_inode_init_security(inode, dir, qstr,
				&hmfs_initxattrs, ipage);
}

const struct xattr_handler hmfs_xattr_trusted_handler = {
	.prefix = XATTR_TRUSTED_PREFIX,
	.flags = HMFS_XATTR_INDEX_TRUSTED,
	.list = hmfs_xattr_generic_list,
	.get = hmfs_xattr_generic_get,
	.set = hmfs_xattr_generic_set,
};

const struct xattr_handler hmfs_xattr_advise_handler = {
	.prefix = HMFS_SYSTEM_ADVISE_PREFIX,
	.flags = HMFS_XATTR_INDEX_ADVISE,
	.list = hmfs_xattr_advise_list,
	.get = hmfs_xattr_advise_get,
	.set = hmfs_xattr_advise_set,
};

const struct xattr_handler hmfs_xattr_security_handler = {
	.prefix = XATTR_SECURITY_PREFIX,
	.flags = HMFS_XATTR_INDEX_SECURITY,
	.list = hmfs_xattr_generic_list,
	.get = hmfs_xattr_generic_get,
	.set = hmfs_xattr_generic_set,
};

const struct xattr_handler hmfs_xattr_user_handler = {
	.prefix = XATTR_USER_PREFIX,
	.flags = HMFS_XATTR_INDEX_USER,
	.list = hmfs_xattr_generic_list,
	.get = hmfs_xattr_generic_get,
	.set = hmfs_xattr_generic_set,
};

static const struct xattr_handler *hmfs_xattr_handler_map[] = {
	[HMFS_XATTR_INDEX_USER] = &hmfs_xattr_user_handler,
#ifdef CONFIG_HMFS_ACL
	[HMFS_XATTR_INDEX_POSIX_ACL_ACCESS] = &hmfs_acl_access_handler,
	[HMFS_XATTR_INDEX_POSIX_ACL_DEFAULT] = &hmfs_acl_default_handler,
#endif
	[HMFS_XATTR_INDEX_TRUSTED] = &hmfs_xattr_trusted_handler,
	[HMFS_XATTR_INDEX_SECURITY] = &hmfs_xattr_security_handler,
	[HMFS_XATTR_INDEX_ADVISE] = &hmfs_xattr_advise_handler,
};

const struct xattr_handler *hmfs_xattr_handlers[] = {
	&hmfs_xattr_user_handler,
	&hmfs_xattr_trusted_handler,
	&hmfs_xattr_advise_handler,
	&hmfs_xattr_security_handler,
	&hmfs_acl_access_handler,
	&hmfs_acl_default_handler,
	NULL,
};
/**
 * @return 返回第index个扩展属性句柄
 */
static inline const struct xattr_handler *hmfs_xattr_handler(int index)
{
	const struct xattr_handler *handler = NULL;
	if (index > 0 && index < ARRAY_SIZE(hmfs_xattr_handler_map))
		handler = hmfs_xattr_handler_map[index];
	return handler;
}
/**
 *将文件的扩展属性名称复制到列表中
 *@param[in] dentry 指向文件目录项
 *@param[in] buffer 指向列表所在缓冲区指针
 *@param[in] buffer_size 为缓冲区大小
 *@return 返回值为正时表示所使用的缓冲区空间大小，返回值为负时表示缓冲区空间不够存储该列表
 */
ssize_t hmfs_listxattr(struct dentry *dentry, char *buffer, size_t buffer_size)
{
	struct inode *inode =dentry->d_inode;
	struct hmfs_xattr_entry *entry;
	void *xattr_block;
	int error = 0;
	size_t size, rest = buffer_size;

	xattr_block  = get_xattr_block(inode);
	if (!xattr_block)
		return -ENODATA;

	list_for_each_xattr(entry, xattr_block) {
		const struct xattr_handler *handler = 
				hmfs_xattr_handler(entry->e_name_index);

		if (!handler)
			continue;

		size = handler->list(dentry, buffer, rest,entry->e_name,
					entry->e_name_len, handler->flags);
		if (buffer && size > rest) {
			error = -ERANGE;
			goto out;
		}

		if (buffer)
			buffer += size;
		rest -= size;
	}
	error = buffer_size - rest;
out:
	return error;
}
