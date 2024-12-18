#ifndef __LINUX_FIVE_FILE_H
#define __LINUX_FIVE_FILE_H

struct file *test_open_file(const char *filename);
void test_close_file(struct file *file);
ssize_t test_write_file(struct file *file, const char __user *buf, size_t count, loff_t *pos);

#endif // __LINUX_FIVE_FILE_H
