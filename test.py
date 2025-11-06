import hashlib

# === 입력 부분 ===
V_hex = "6E2F8FE3CDCD8942BC19890B70E89DD37EF46DFBDC17C209941B1B236417B3704AE2E5BBBF289500068FD45B6B40B69C78944F611255CF"
requested_bits = 1024  # 로그에서 복사한 값
outlen_bits = 256  # SHA-256 output length in bits

# === 변환 ===
V = bytes.fromhex(V_hex)
requested_bytes = (requested_bits + 7) // 8
outlen_bytes = outlen_bits // 8

def increment_big_endian(buf: bytearray):
    """Increment big-endian bytearray by 1 (mod 2^(8*len))."""
    carry = 1
    for i in range(len(buf)-1, -1, -1):
        val = buf[i] + carry
        buf[i] = val & 0xFF
        carry = val >> 8
        if not carry:
            break

def hashgen(V: bytes, requested_bits: int):
    data = bytearray(V)
    W = b""
    m = (requested_bits + outlen_bits - 1) // outlen_bits

    print(f"[PYDBG] requested_bits={requested_bits}  m={m}")
    print(f"[PYDBG] Initial V={V.hex().upper()}")

    for i in range(m):
        h = hashlib.sha256(bytes(data)).digest()
        W += h
        print(f"[PYDBG] i={i} data={data.hex().upper()} hash={h.hex().upper()}")
        increment_big_endian(data)

    return W[:requested_bytes]

# === 수행 ===
result = hashgen(V, requested_bits)

print(f"\n[PYDBG] Leftmost(W)={result.hex().upper()}")
print(f"[PYDBG] Length={len(result)} bytes ({len(result)*8} bits)")
