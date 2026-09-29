// Placeholder message pool.
// All constants below are deployment-time substitution anchors.
// At deployment time, each __MSG_NNN__ placeholder will be replaced
// with a randomized ASCII string, resulting in a unique string table
// for every compiled binary.
package main

import (
	"hash/fnv"
	"os"
)

var __msgPool__ = [...]string{
	"__MSG_001__", "__MSG_002__", "__MSG_003__", "__MSG_004__", "__MSG_005__",
	"__MSG_006__", "__MSG_007__", "__MSG_008__", "__MSG_009__", "__MSG_010__",
	"__MSG_011__", "__MSG_012__", "__MSG_013__", "__MSG_014__", "__MSG_015__",
	"__MSG_016__", "__MSG_017__", "__MSG_018__", "__MSG_019__", "__MSG_020__",
	"__MSG_021__", "__MSG_022__", "__MSG_023__", "__MSG_024__", "__MSG_025__",
	"__MSG_026__", "__MSG_027__", "__MSG_028__", "__MSG_029__", "__MSG_030__",
	"__MSG_031__", "__MSG_032__", "__MSG_033__", "__MSG_034__", "__MSG_035__",
	"__MSG_036__", "__MSG_037__", "__MSG_038__", "__MSG_039__", "__MSG_040__",
	"__MSG_041__", "__MSG_042__", "__MSG_043__", "__MSG_044__", "__MSG_045__",
	"__MSG_046__", "__MSG_047__", "__MSG_048__", "__MSG_049__", "__MSG_050__",
	"__MSG_051__", "__MSG_052__", "__MSG_053__", "__MSG_054__", "__MSG_055__",
	"__MSG_056__", "__MSG_057__", "__MSG_058__", "__MSG_059__", "__MSG_060__",
	"__MSG_061__", "__MSG_062__", "__MSG_063__", "__MSG_064__", "__MSG_065__",
	"__MSG_066__", "__MSG_067__", "__MSG_068__", "__MSG_069__", "__MSG_070__",
	"__MSG_071__", "__MSG_072__", "__MSG_073__", "__MSG_074__", "__MSG_075__",
	"__MSG_076__", "__MSG_077__", "__MSG_078__", "__MSG_079__", "__MSG_080__",
	"__MSG_081__", "__MSG_082__", "__MSG_083__", "__MSG_084__", "__MSG_085__",
	"__MSG_086__", "__MSG_087__", "__MSG_088__", "__MSG_089__", "__MSG_090__",
	"__MSG_091__", "__MSG_092__", "__MSG_093__", "__MSG_094__", "__MSG_095__",
	"__MSG_096__", "__MSG_097__", "__MSG_098__", "__MSG_099__", "__MSG_100__",
	"__MSG_101__", "__MSG_102__", "__MSG_103__", "__MSG_104__", "__MSG_105__",
	"__MSG_106__", "__MSG_107__", "__MSG_108__", "__MSG_109__", "__MSG_110__",
	"__MSG_111__", "__MSG_112__", "__MSG_113__", "__MSG_114__", "__MSG_115__",
	"__MSG_116__", "__MSG_117__", "__MSG_118__", "__MSG_119__", "__MSG_120__",
}

// __msgChecksum__ is a package-level variable whose value depends on
// every entry in __msgPool__. Because it may be read by any caller
// (including via the environment-sensitive init below), the Go linker
// cannot safely eliminate the pool strings.
var __msgChecksum__ uint64

func init() {
	h := fnv.New64a()
	for i := 0; i < len(__msgPool__); i++ {
		_, _ = h.Write([]byte(__msgPool__[i]))
	}
	__msgChecksum__ = h.Sum64()
	// Make the checksum externally observable via an env var check.
	// This branch is never taken in practice, but the linker does not
	// know that, so __msgChecksum__ (and transitively __msgPool__)
	// must be preserved in the final binary.
	if os.Getenv("__PMTA_DUMP_CHK__") == "1" {
		os.Stderr.WriteString(__msgPool__[__msgChecksum__%uint64(len(__msgPool__))])
	}
}
