/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023. Huawei Technologies Co., Ltd. All rights reserved.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#ifndef __QTFS_LOG_H__
#define __QTFS_LOG_H__

#include <linux/string.h>
#include "comm.h"

enum level {
	LOG_NONE,
	LOG_ERROR,
	LOG_WARN,
	LOG_INFO,
	LOG_DEBUG
};

extern int log_level;

#define qtfs_crit(fmt, ...) \
	{\
		pr_crit("[%s::%s:%4d] " fmt,\
			KBUILD_MODNAME, kbasename(__FILE__), __LINE__, ##__VA_ARGS__);\
	}

#define qtfs_err(fmt, ...) 	\
(								\
	{							\
	if (likely(log_level >= LOG_ERROR)) {	\
		pr_err("[%s::%s:%4d] " fmt,	\
			KBUILD_MODNAME, kbasename(__FILE__), __LINE__, ##__VA_ARGS__);	\
	}							\
}								\
)

static inline int qtfs_log_init(char *level, int len) {
	if (!strcmp(level, "WARN")) {
		log_level = LOG_WARN;
	} else if (!strcmp(level, "INFO")) {
		log_level = LOG_INFO;
	} else if (!strcmp(level, "DEBUG")) {
		log_level = LOG_DEBUG;
	} else if (!strcmp(level, "NONE")) {
		log_level = LOG_NONE;
	} else if(!strcmp(level, "ERROR")){
		log_level = LOG_ERROR;
	} else {
		qtfs_err("qtfs log set failed, unknown type:%s.", level);
		return QTERROR;
	}
	return QTOK;
}


#define qtfs_warn(fmt, ...) 	\
(								\
	{							\
	if (unlikely(log_level >= LOG_WARN)) {	\
		pr_warn("[%s::%s:%4d] " fmt,	\
			KBUILD_MODNAME, kbasename(__FILE__), __LINE__, ##__VA_ARGS__);	\
	}							\
}								\
)

#define qtfs_info(fmt, ...) 	\
(								\
{								\
	if (unlikely(log_level >= LOG_INFO)) {	\
		pr_info("[%s::%s:%4d] " fmt,	\
			KBUILD_MODNAME, kbasename(__FILE__), __LINE__, ##__VA_ARGS__);	\
	}							\
}								\
)

#define qtfs_debug(fmt, ...) 	\
(								\
{								\
	if (unlikely(log_level >= LOG_DEBUG)) {	\
		pr_info("[%s::%s:%4d] " fmt, \
			KBUILD_MODNAME, kbasename(__FILE__), __LINE__, ##__VA_ARGS__);	\
	}							\
}								\
)

#define qtfs_err_ratelimited(fmt, ...) 	\
(								\
	{							\
	if (likely(log_level >= LOG_ERROR)) {	\
		pr_err_ratelimited("[%s::%s:%4d] " fmt,	\
			KBUILD_MODNAME, kbasename(__FILE__), __LINE__, ##__VA_ARGS__);	\
	}							\
}								\
)

#define qtfs_info_ratelimited(fmt, ...) \
(								\
{								\
	if (unlikely(log_level >= LOG_INFO)) {	\
		pr_info_ratelimited("[%s::%s:%4d] " fmt,	\
			KBUILD_MODNAME, kbasename(__FILE__), __LINE__, ##__VA_ARGS__);	\
	}							\
}								\
)

#define qtfs_warn_ratelimited(fmt, ...) \
(								\
{								\
	if (unlikely(log_level >= LOG_WARN)) {	\
		pr_warn_ratelimited("[%s::%s:%4d] " fmt,	\
			KBUILD_MODNAME, kbasename(__FILE__), __LINE__, ##__VA_ARGS__);	\
	}							\
}								\
)


#endif
