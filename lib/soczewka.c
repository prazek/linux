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

int should_not_scan(void) {
    return has_capability(current, CAP_SYS_SOCZEWKA_IMMUNE);
}

static void scan(const char *mem, unsigned long size);

void soczewka_scan_mem(const void *from, unsigned long n) {
   if (unlikely(should_not_scan()))
       return;
    scan(from, n);
}


#define MAX_NUM_DANGEROUS_WORDS  \
    (sizeof(((struct task_struct*)(NULL))->soczewka_reported_words) * __CHAR_BIT__)
#define MAX_LEN_DANGEROUS_WORD   64

_Static_assert(MAX_NUM_DANGEROUS_WORDS == 
        sizeof(((struct task_struct*)(NULL))->soczewka_reported_words) * __CHAR_BIT__,
        "size of supported dangerous word need to fit");

static char dangerous_words[MAX_NUM_DANGEROUS_WORDS][MAX_LEN_DANGEROUS_WORD + 1];
static int dangerous_words_count = 0;

static int setup_soczewka(char *str) {
    char *last_begin = str;
    char *token = NULL;
    int cur_word_num = 0;

    while ((token = strsep(&str, ","))) {
        if (token - last_begin > MAX_LEN_DANGEROUS_WORD) {
            printk(KERN_ERR "soczewka: one of dangerous word too long. Limit is %d",
                    MAX_LEN_DANGEROUS_WORD);
            return 0; // TODO
        }
        if (cur_word_num > MAX_NUM_DANGEROUS_WORDS) {
            printk(KERN_ERR "soczewka: too many dangerous words. Limit is %ld\n",
                    MAX_NUM_DANGEROUS_WORDS);    
            return 0; // TODO
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


// TODO 256
#define LEN_WORDS_BEFORE    3
#define LEN_WORDS_AFTER     3

static void str_bytes(char *to_write, const char *mem, int size) {
    int i;
    char *cur_to_write = to_write;
    for (i = 0; i < size; i++) {
        cur_to_write += sprintf(cur_to_write, "%x ", mem[i]);
    }
    *(cur_to_write - 1) = '\0';
}


static void report(struct task_struct *task, 
        const char* dangerous_word,
        const char *mem, const char *found_pos, unsigned long size) {
    char before_bytes[LEN_WORDS_BEFORE*3 + 1];
    char after_bytes[LEN_WORDS_AFTER*3 + 1];
    int bytes_before;
    int bytes_after;
    const char *end_found_pos;
    
    bytes_before = (mem + LEN_WORDS_BEFORE < found_pos) ? 
        LEN_WORDS_BEFORE : found_pos - mem;
    str_bytes(before_bytes, mem, bytes_before);
    
    end_found_pos = found_pos + strlen(dangerous_word);
    bytes_after = (end_found_pos + LEN_WORDS_AFTER < mem + size)? 
        LEN_WORDS_AFTER : mem + size - end_found_pos;
    str_bytes(after_bytes, end_found_pos, bytes_after);

    printk(KERN_WARNING "soczewka: PID %d UID %d GID %d %s before [%s] after [%s]\n",
        task->pid, current_cred()->uid.val, task->tgid, dangerous_word, before_bytes,
        after_bytes);

}

static void scan(const char *mem, unsigned long size) {

    struct task_struct *task = current;
    const char *dangerous_word;
    int word;
    const char *found_pos;
    
    for (word = 0; word < dangerous_words_count; word++) {
        if (test_bit(word, &task->soczewka_reported_words))
            continue;
        dangerous_word = dangerous_words[word];
        found_pos = strnstr(mem, dangerous_word, size);
        if (likely(found_pos == NULL))
            continue;
        
        // set reported bit and proceed if no one else set up the bit in the meantime
        if (unlikely(test_and_set_bit(word, &task->soczewka_reported_words)))
            continue;
        report(task, dangerous_word, mem, found_pos, size);
    } 
}

