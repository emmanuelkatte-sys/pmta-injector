package email

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"math/rand"
	"strings"
)

// 【Haraka26】图片噪点模块
// 对 JPG/PNG 图片添加随机噪点 + 尾部随机字节，
// 用于附件与 CID 内联图，使每封邮件的图片 MD5/SHA256 都不同。

// AddImageNoise 给图片添加噪点（修改 1-5 个像素 + 尾部追加随机字节）
// 只支持 JPEG 和 PNG 格式，其他格式直接返回原始数据
func AddImageNoise(imgBytes []byte, filename string) []byte {
	lowerName := strings.ToLower(filename)

	var isJPEG, isPNG bool
	if strings.HasSuffix(lowerName, ".jpg") || strings.HasSuffix(lowerName, ".jpeg") {
		isJPEG = true
	} else if strings.HasSuffix(lowerName, ".png") {
		isPNG = true
	}

	if !isJPEG && !isPNG {
		// 不支持的格式，只追加尾部随机字节
		return appendTrailingNoise(imgBytes)
	}

	// 解码图片
	reader := bytes.NewReader(imgBytes)
	img, _, err := image.Decode(reader)
	if err != nil {
		// 解码失败，只追加尾部随机字节
		return appendTrailingNoise(imgBytes)
	}

	// 转为可修改的 RGBA 图片
	bounds := img.Bounds()
	rgba := image.NewRGBA(bounds)
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			rgba.Set(x, y, img.At(x, y))
		}
	}

	// 修改 1-5 个随机像素（在原始颜色基础上微调 ±1-3 RGB 值）
	pixelCount := 1 + rand.Intn(5)
	width := bounds.Dx()
	height := bounds.Dy()
	if width < 1 || height < 1 {
		return appendTrailingNoise(imgBytes)
	}

	for i := 0; i < pixelCount; i++ {
		x := bounds.Min.X + rand.Intn(width)
		y := bounds.Min.Y + rand.Intn(height)
		origColor := rgba.At(x, y)
		r, g, b, a := origColor.RGBA()

		// 微调 RGB（±1-3），肉眼不可见
		newR := clampU8(int(r>>8) + rand.Intn(7) - 3)
		newG := clampU8(int(g>>8) + rand.Intn(7) - 3)
		newB := clampU8(int(b>>8) + rand.Intn(7) - 3)
		rgba.Set(x, y, color.RGBA{R: newR, G: newG, B: newB, A: uint8(a >> 8)})
	}

	// 重新编码
	var buf bytes.Buffer
	if isJPEG {
		// JPEG 用随机质量（90-95），进一步增加字节差异
		quality := 90 + rand.Intn(6)
		err = jpeg.Encode(&buf, rgba, &jpeg.Options{Quality: quality})
	} else {
		err = png.Encode(&buf, rgba)
	}

	if err != nil {
		return appendTrailingNoise(imgBytes)
	}

	// 追加尾部随机字节
	return appendTrailingNoise(buf.Bytes())
}

// appendTrailingNoise 在图片文件末尾追加 4-16 字节随机数据
// JPEG/PNG 解码器会忽略尾部多余数据，但文件哈希完全不同
func appendTrailingNoise(data []byte) []byte {
	noiseLen := 4 + rand.Intn(13) // 4-16 字节
	noise := make([]byte, noiseLen)
	for i := range noise {
		noise[i] = byte(rand.Intn(256))
	}
	return append(data, noise...)
}

// clampU8 将整数限制在 0-255 范围内
func clampU8(v int) uint8 {
	if v < 0 {
		return 0
	}
	if v > 255 {
		return 255
	}
	return uint8(v)
}
