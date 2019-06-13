/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/soczewka.h>
#include <linux/cred.h>
#include <linux/export.h>
#include <linux/printk.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <uapi/linux/capability.h>
#include <linux/string.h>

_Static_assert(SOCZEWKA_MAX_NUM_DANGEROUS_WORDS == 
		sizeof(((struct task_struct*)(NULL))->soczewka_reported_words) * __CHAR_BIT__,
		"size of supported dangerous word need to fit");


static int should_not_scan(void) {
		return has_capability(current, CAP_SYS_SOCZEWKA_IMMUNE);
}

static void scan(const char *mem, unsigned long size);

void soczewka_scan_mem(const void *from, unsigned long n) {
	if (unlikely(should_not_scan()))
				return;
		scan(from, n);
}

static char dangerous_words[SOCZEWKA_MAX_NUM_DANGEROUS_WORDS][SOCZEWKA_MAX_LEN_DANGEROUS_WORD + 1];
static int dangerous_words_count = 0;

static int setup_soczewka(char *str) {
	char *last_begin = str;
	char *token = NULL;
	int cur_word_num = 0;

	while ((token = strsep(&str, ","))) {
		if (token - last_begin > SOCZEWKA_MAX_LEN_DANGEROUS_WORD) {
			printk(KERN_ERR "soczewka: one of dangerous word too long. Limit is %d",
					SOCZEWKA_MAX_LEN_DANGEROUS_WORD);
			return 0;
		}
		if (cur_word_num > SOCZEWKA_MAX_NUM_DANGEROUS_WORDS) {
			printk(KERN_ERR "soczewka: too many dangerous words. Limit is %d\n",
					SOCZEWKA_MAX_NUM_DANGEROUS_WORDS);	 
			return 0;
		}

		strcpy(dangerous_words[cur_word_num], last_begin);
		printk(KERN_DEBUG "soczewka: word=[%s]\n", dangerous_words[cur_word_num]);
		last_begin = token;
		cur_word_num++;
	}

	dangerous_words_count = cur_word_num;
	return 1;
}

__setup("soczewka=", setup_soczewka);

#define LEN_WORDS_BEFORE	256
#define LEN_WORDS_AFTER		256

static void str_bytes(char * const to_write, const char *from, const char* to) {
	char *cur_to_write = to_write;
	BUG_ON(from > to);
	BUG_ON(to - from > LEN_WORDS_BEFORE);
	
	for (; from < to; from++) {
		cur_to_write += sprintf(cur_to_write, "%02x ", (unsigned char)*from);
	}

	if (cur_to_write != to_write)
		*(cur_to_write - 1) = '\0';
	if (cur_to_write - to_write > LEN_WORDS_BEFORE*3 + 1)
			printk(KERN_ERR "diff %ld", cur_to_write - to_write);
}

DEFINE_SPINLOCK(report_lock);
static char before_bytes[LEN_WORDS_BEFORE*3 + 3];
static char after_bytes[LEN_WORDS_AFTER*3 + 3];

static void report(struct task_struct *task, 
		const char* dangerous_word,
		const char *mem, const char *found_pos, unsigned long size) {
	const char *bytes_before_beg;
	const char *bytes_after_end;
	const char *end_found_pos;
	
	spin_lock(&report_lock);
	bytes_before_beg = (mem + LEN_WORDS_BEFORE < found_pos) ? 
		found_pos - LEN_WORDS_BEFORE: mem;
	str_bytes(before_bytes, bytes_before_beg, found_pos);

	end_found_pos = found_pos + strlen(dangerous_word);
	bytes_after_end = (end_found_pos + LEN_WORDS_AFTER < mem + size)? 
		end_found_pos + LEN_WORDS_AFTER : mem + size;
	str_bytes(after_bytes, end_found_pos, bytes_after_end);

	printk(KERN_WARNING "soczewka: PID %d UID %d GID %d %s before [%s] after [%s]\n",
			task->pid, current_cred()->uid.val, task->tgid, dangerous_word, before_bytes,
			after_bytes);
	spin_unlock(&report_lock);
}

static void scan(const char *mem, unsigned long size) {

	struct task_struct *task = current;
	const char *dangerous_word;
	int word;
	const char *found_pos;

	for (word = 0; word < dangerous_words_count; word++) {
		if (test_bit(word, task->soczewka_reported_words))
			continue;
		dangerous_word = dangerous_words[word];
		found_pos = strnstr(mem, dangerous_word, size);
		if (likely(found_pos == NULL))
			continue;

		// set reported bit and proceed if no one else set up the bit in the meantime
		if (unlikely(test_and_set_bit(word, task->soczewka_reported_words)))
			continue;
		report(task, dangerous_word, mem, found_pos, size);
	} 
}

