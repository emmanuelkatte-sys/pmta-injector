package email

import (
	crypto_rand "crypto/rand"
	"encoding/binary"
	"math/rand"
	"time"
)

// ===== 【v62修复】安全随机数工具 =====
// 解决 v60 中 100 个 worker 在纳秒级循环内创建时 seed 重复，
// 导致 math/rand 内部状态退化，Intn(n) 返回越界值 n 的致命 bug

// cryptoSeed 使用 crypto/rand 生成真随机 seed
// 加上 workerID 偏移，确保每个 worker 的随机序列完全独立，彻底避免 seed 碰撞
func cryptoSeed(workerID int) int64 {
	var b [8]byte
	if _, err := crypto_rand.Read(b[:]); err != nil {
		// crypto/rand 失败时的降级方案（极罕见，通常仅在 /dev/urandom 不可用时）
		// 使用大质数乘以 workerID 拉开间距，避免相邻 worker 的 seed 过于接近
		return time.Now().UnixNano() + int64(workerID)*1000000007
	}
	return int64(binary.LittleEndian.Uint64(b[:])) + int64(workerID)
}

// safeIntn 安全的随机整数生成，保证返回值在 [0, n) 范围内
// 【v63修复】不再调用 Intn()（其返回值的边界检查会被编译器 BCE 优化掉）
// 改用 Int63() + 取模运算：Int63() 返回 [0, 2^63)，% n 在数学上保证结果 [0, n-1]
// 编译器不可能优化掉取模运算，因此这是从数学层面保证安全，无需任何运行时检查
func safeIntn(r *rand.Rand, n int) int {
	if n <= 0 {
		return 0
	}
	return int(r.Int63() % int64(n))
}

// 【2026-06-15】randIntRange 返回 [min,max] 内随机整数。
// 先把 min/max 夹紧到 [lo,hi] 并处理 min>max（交给 max=min），永不 panic、永不越界。
func randIntRange(r *rand.Rand, min, max, lo, hi int) int {
	if lo < 0 {
		lo = 0
	}
	if min < lo {
		min = lo
	}
	if max > hi {
		max = hi
	}
	if max < min {
		max = min
	}
	return min + safeIntn(r, max-min+1)
}

// 【2026-06-15】randStringFrom 从 alphabet 随机取 n 个字符组成串（n<=0 或空表 返回空串）。
func randStringFrom(r *rand.Rand, n int, alphabet string) string {
	if n <= 0 || len(alphabet) == 0 {
		return ""
	}
	out := make([]byte, n)
	for i := range out {
		out[i] = alphabet[safeIntn(r, len(alphabet))]
	}
	return string(out)
}
