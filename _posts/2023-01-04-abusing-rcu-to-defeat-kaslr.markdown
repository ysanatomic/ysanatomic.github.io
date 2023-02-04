---
layout: post
title:  "Abusing RCU callbacks with a Use-After-Free read to defeat KASLR"
permalink: /abusing_rcu_callbacks_to_defeat_kaslr/
date:   2023-01-04 17:00:00 +0300
---
## Introduction
In this article, I will be walking you through a clever technique that can be used to leak addresses and defeat KASLR in the Linux Kernel when you have a certain type of Use-After-Free by abusing RCU callbacks. It is by no means a novel technique and has most likely been leveraged in several exploits.

This is a guide meant to give you a solid understanding of the technique as quickly as possible.
> This article was supposed to come out 2 weeks ago but it was delayed due to the Christmas holidays.

## Table of Contents
1. [The Technique in a nutshell](#technique)
2. [Criteria](#criteria)
	+ [A certain type of Use-After-Free](#uaf)
	+ [A specific OOB read](#oobread)
	+ [Ability to spray objects](#spray)
3. [Analysis](#analysis)
	+ [Reading Primitive](#reading_primitive)
		+ [user_key_payload](#user_key_payload)
		+ [posix_msg_tree_node](#posix_msg_tree_node)
		+ [msg_msg](#msg_msg)
	+ [Frankensteining everything together](#frankenstein)
4. [Resources](#resources)
5. [Summary](#summary)

## The Technique in a nutshell <a name="technique"></a>
The technique is possible when we control two objects allocated next to each other in the same slab cache. We must be able to read out-of-bounds through the first object while the second object must have a `rcu_head` as its first member.

If we make a call to update the second object the kernel will call `call_rcu` which will populate `rcu_head->func()`. Then if we can read OOB through the first object into the second object's `rcu_head` without sleeping (as to not let the kernel execute `rcu_head->func()` which will free the memory and maybe zero it out if sensitive) we will be able to leak the address in `rcu_head->func()` therefore defeating KASLR.

Now that we have a general summary of the technique it is time to go more in-depth.

## Criteria <a name="criteria"></a>
We have some criteria that have to be met to be able to use this technique.

### A certain type of Use-After-Free <a name="uaf"></a>
This technique applies to objects that meet the following requirements: 
- The object that gets UAF'd must be in a linked list.
- The `list_head` of the object must be at offset 16 bytes or more relative to the start of the object.
- You must be able to get multiple objects that get UAF'd in a linked list with one another.

### A specific OOB read <a name="oobread"></a>
We need to have a primitive capable of reading at least 16 bytes out-of-bounds for the slab object. However, it is important to mention that read sizes cannot go over the size limit of the slab cache. So if you are reading from an object in kmalloc-64 you can read up to 64 bytes before the kernel detects the memory leak if the option `CONFIG_HARDENED_USERCOPY` is on (and chances are it is on the target). This means that your read needs to start at offset 16 bytes from the start of the slab object to be able to read 16 bytes out-of-bounds. 

>Ex: If you have a `kmalloc-64` slab object that occupies the address space from address `0x20` to address `0x60` your read must start at offset `0x30` to be able to read 16 bytes out-of-bounds for the slab object (up to `0x70`). 

It might be a little difficult to find OOB read primitives like this but they exist even if somewhat conditionally (those OOB reads could only be achieved if the previous conditions about the type of Use-After-Free are met). More on that later.

### Ability to spray objects <a name="spray"></a>
We need to be able to spray objects that have `rcu_head` as their first member. We must also be able to 'update' those objects. 

> The objects that will be sprayed must be allocated with the same GFP flag as the primitive that is used for reading. Otherwise, they won't be allocated in the same caches.

## Analysis <a name="analysis"></a>
I will provide a simple (fake) example case and go over how the technique could be applied. 
> For a real case where this technique is used: I have a write-up coming out soon of a vulnerability where I use this very trick to leak an address and bypass KASLR.

Let's have a type `vuln_obj` 
```c
struct vuln_obj {
	uint64_t int1; // @0
	uint64_t int2; // @8
	uint64_t int3; // @16
	struct list_head list; // @24 - matches the requirement for the list_head 
	unsigned char data[16]; // @40
}
```
We can freely make calls to the kernel that will allocate this structure with the flag `GFP_KERNEL`. All objects of this type are allocated in `kmalloc-64` and all objects of this type are in a linked list together. We can also make calls to free structures of this type. However, the kernel does not unlink the object that gets freed from the linked list. 

This is our vulnerability: a `vuln_obj` object gets freed but it is not removed from the linked list and the previous and next objects in the list hold pointers to it. This causes a Use-After-Free and `vuln_obj` meets all the criteria we set prior.

### Read Primitive <a name="reading_primitive"></a>
Now that we have introduced our example vulnerable object we need to look for a read primitive that matches the conditions we set earlier.

A primitive like that won't be found just laying around - we need to work a bit to get it. Our `vuln_obj` is allocated in `kmalloc-64` so we are looking for objects that get allocated in that slab cache. In this example, we are going to be leveraging objects belonging to the **in-kernel key management and retention facility** and the **message queue** system of the kernel.

#### user_key_payload <a name="user_key_payload"></a>
Objects of type `user_key_payload` hold the payload of **user and logon keys**. This type plays the main role in our story.
```c
/* include/keys/user-type.h */
struct user_key_payload {
	struct rcu_head	rcu;		/* RCU destructor */ // @0 - 16 bytes
	unsigned short	datalen;	/* length of payload */ // @16 - 2 bytes
	char		data[] __aligned(__alignof__(u64)); /* actual payload */ // @24
};

struct callback_head {
	struct callback_head *next; // @0
	void (*func)(struct callback_head *head); // @8 rcu_head->func 
} __attribute__((aligned(sizeof(void *))));
#define rcu_head callback_head
```
This object will be the one we will leak KASLR through (by reading the `rcu->func` pointer at offset 16 bytes).

#### posix_msg_tree_node <a name="posix_msg_tree_node"></a>
In the message queue subsystem, all the messages (`struct msg_msg`) belonging to a certain queue are in a linked list together. The start (the root) of the queue is a `struct posix_msg_tree_node`.
```c
struct posix_msg_tree_node {
    struct rb_node      rb_node; // of size 0x18 = 24 bytes
    struct list_head    msg_list; // @24 (is 16 bytes)
    int         priority; // @40
};

struct rb_node {
    unsigned long  __rb_parent_color;
    struct rb_node *rb_right;
    struct rb_node *rb_left;
} __attribute__((aligned(sizeof(long))));
```
It is allocated with the `GFP_KERNEL` flag and as such will be allocated in the same caches as our `vuln_obj`.
> However interestingly enough messages in the queue are allocated with the flag GFP_KERNEL_ACCOUNT and reside in the kmalloc-cg-n caches. So in our case msg_msg is not a viable primitive.

We do not possess direct control over objects of this type but we can freely allocate them by creating message queues.
> Technically the posix_msg_tree_node for each queue gets initiated whenever the first message is added to the queue and not when the queue is created.

Lets check how `posix_msg_tree_node` overlaps over `vuln_obj`
```
Obj: vuln_obj ; posix_msg_tree_node
@0:  int1     ; _rb_parent_color
@8:  int2     ; *rb_right
@16: int3     ; *rb_left
@24: list     ; msg_list 
```
Here `posix_msg_tree_node` is suitable as a primitive because the linked list `msg_list` aligns with `vuln_obj.list` (at offset 24 bytes). 

If we manage to allocate `posix_msg_tree_node` in the same slab object where a `vuln_obj` used to reside we could influence the `msg_list->*next` and `msg_list->*prev` via the use-after-free (by initiating other `vuln_obj` objects).

#### msg_msg <a name="msg_msg"></a>
This structure holds messages belonging to the message queue system of the kernel. 
```c
/* one msg_msg structure for each message */
struct msg_msg {
	struct list_head m_list; // @0
	long m_type; // @16
	size_t m_ts;	// @24	/* message text size */
	struct msg_msgseg *next; // @32
	void *security; // @40
	/* the actual message follows immediately */
};
```
It is important to note:
- `*security` must always hold a valid address to heap memory 
- The `list_head` of the linked list with all the messages in the queue is **at the start** of the object (in contrast to `vuln_obj` where it is at offset 24 bytes).

### Frankensteining everything together <a name="frankenstein"></a>
Now that we have introduced the objects we need to **frankenstein** them together to achieve the OOB read we need to leak KASLR.

To achieve that we have to do the following:
- Make a call to allocate a `vuln_obj` object and free it (we shall call this Object 1).
- Allocate a `posix_msg_tree_node` of a queue at the UAF'd (Object 1) location.
- Initiate a new `vuln_obj` that gets UAF'd (Object 2). The address of `vuln_obj.list` will get written in `posix_msg_tree_node.msg_list.next` so the kernel will be fooled to believe that the first message in the message queue starts at `vuln_obj.list`. However `vuln_obj.list` is at an offset of 24 bytes while `msg_msg.m_list` is at an offset of 0 bytes from the start of the slab object. Therefore we can get 24 bytes of OOB read by reading the first message in the queue. (take a look at diagram for clarity)
- Allocate a `user_key_payload` where *Object 2* used to be and pass valid heap addresses for `m_list->next` and `m_list->prev` (you need to have leaked a heap address for this - out of scope for this article but could be easily done in our example).
- Allocate a `user_key_payload` right under *Object 2* (this is the payload object whose `rcu->func` we leak).
- Make a call to change the `user_key_payload` that is allocated under *Object 2*.
- Immediately make a call to fetch the first message in the message queue (with a bit of luck `rcu->func()` wouldn't have been called yet).
- And we have the `.text` address - defeating KASLR.

> This is a simplification. In reality, to do this reliably you need to spray a ton of `user_key_payload` objects to get one right under Object 2. Then you need to mass edit all the payloads and then fetch the first message in the queue.

> We said prior that `*security` always needs to hold a valid heap address. We don't have to worry about that as it will overlap with `rcu_head->next`.

![diagram](https://i.imgur.com/oQMWv87.png)

## Resources <a name="resources"></a>
Some resources you might want to check out.

1. [What is RCU?](https://www.kernel.org/doc/Documentation/RCU/whatisRCU.txt)
2. [mq_overview](https://man7.org/linux/man-pages/man7/mq_overview.7.html)
3. [keyrings](https://man7.org/linux/man-pages/man7/keyrings.7.html)

## Summary <a name="summary"></a>
I provided an example which allows the use of this technique. The fake example is very close to the real application of the technique in my next vulnerability write-up (which should be coming out in the next week or two). 

I believe the analysis and explanation are not too difficult to grasp but if you have questions feel free to reach out to me.

Keep an eye out for when the write-up drops if you are interested in the *"real life"* application.

