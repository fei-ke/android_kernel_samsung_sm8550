#ifndef __LINUX_PROCA_AUDIT_H
#define __LINUX_PROCA_AUDIT_H

#include <linux/task_integrity.h>

void proca_audit_err(struct task_struct *task, struct file *file,
		const char *op, const char *cause);

#endif
