package apk

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"hash/crc32"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/Helix2010/RN-Server/signing/apk/axml"
)

const (
	sigEOCD             = 0x06054b50
	sigZip64Locator     = 0x07064b50
	sigCentralDirectory = 0x02014b50
	sigLocalHeader      = 0x04034b50
	sigDataDescriptor   = 0x08074b50

	eocdSize        = 22
	cdRecordSize    = 46
	localHeaderSize = 30
	maxCommentSize  = 0xffff

	flagEncrypted       = 1 << 0
	flagDataDescriptor  = 1 << 3
	flagStrongEncrypted = 1 << 6
	flagMaskedHeaders   = 1 << 13

	methodStored  = 0
	methodDeflate = 8

	extraZip64 = 0x0001

	signingBlockMagic = "APK Sig Block 42"
	// 块结构：u64 size | 键值对 | u64 size | 16 字节 magic；size 不含开头那 8 字节
	signingBlockMinSize = 8 + 8 + 16
	// apksigner 把签名块对齐到的页大小
	signingBlockPageSize = 4096

	storedAlignment = 4
	pageAlignment   = 16384
)

type zipFile struct {
	r            io.ReaderAt
	entries      []Entry
	byName       map[string]Entry
	signingBlock bool
}

func readAt(r io.ReaderAt, off, n int64) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := r.ReadAt(buf, off); err != nil {
		return nil, errorf(CodeReadFailed, "cannot read %d bytes at offset %d: %v", n, off, err)
	}
	return buf, nil
}

func readZip(r io.ReaderAt, size int64, lim Limits) (*zipFile, error) {
	if size < eocdSize {
		return nil, errorf(CodeZipNoEOCD, "file is too small to be a ZIP archive")
	}
	tailSize := int64(eocdSize + maxCommentSize)
	if tailSize > size {
		tailSize = size
	}
	tail, err := readAt(r, size-tailSize, tailSize)
	if err != nil {
		return nil, err
	}
	// 从文件末尾往前找：签名匹配、注释长度恰好让 EOCD 结束在文件末尾
	eocdInTail := -1
	for i := len(tail) - eocdSize; i >= 0; i-- {
		if binary.LittleEndian.Uint32(tail[i:]) != sigEOCD {
			continue
		}
		commentLen := int(binary.LittleEndian.Uint16(tail[i+20:]))
		if i+eocdSize+commentLen == len(tail) {
			eocdInTail = i
			break
		}
	}
	if eocdInTail < 0 {
		return nil, errorf(CodeZipNoEOCD, "no end-of-central-directory record ends at the end of the file")
	}
	eocd := tail[eocdInTail:]
	eocdOffset := size - tailSize + int64(eocdInTail)
	disk := binary.LittleEndian.Uint16(eocd[4:])
	cdDisk := binary.LittleEndian.Uint16(eocd[6:])
	entriesOnDisk := binary.LittleEndian.Uint16(eocd[8:])
	entriesTotal := binary.LittleEndian.Uint16(eocd[10:])
	cdSize := binary.LittleEndian.Uint32(eocd[12:])
	cdOffset := binary.LittleEndian.Uint32(eocd[16:])
	commentLen := binary.LittleEndian.Uint16(eocd[20:])
	if commentLen != 0 {
		return nil, errorf(CodeZipComment, "the archive has a %d byte comment", commentLen)
	}
	if entriesOnDisk == 0xffff || entriesTotal == 0xffff || cdSize == 0xffffffff || cdOffset == 0xffffffff {
		return nil, errorf(CodeZip64Unsupported, "the end-of-central-directory record uses zip64 sentinels")
	}
	if eocdOffset >= 20 {
		locator, err := readAt(r, eocdOffset-20, 4)
		if err != nil {
			return nil, err
		}
		if binary.LittleEndian.Uint32(locator) == sigZip64Locator {
			return nil, errorf(CodeZip64Unsupported, "the archive has a zip64 end-of-central-directory locator")
		}
	}
	if disk != 0 || cdDisk != 0 {
		return nil, errorf(CodeZipMultiDisk, "multi-disk archives are not supported")
	}
	if entriesOnDisk != entriesTotal {
		return nil, errorf(CodeZipCDBounds, "entries on disk (%d) differ from total entries (%d)", entriesOnDisk, entriesTotal)
	}
	if int64(cdOffset)+int64(cdSize) != eocdOffset {
		return nil, errorf(CodeZipCDBounds, "the central directory (offset %d, size %d) does not end at the end-of-central-directory record (%d)", cdOffset, cdSize, eocdOffset)
	}
	if int(entriesTotal) > lim.MaxEntries {
		return nil, errorf(CodeZipTooManyEntries, "the archive has %d entries, over the %d limit", entriesTotal, lim.MaxEntries)
	}
	if int64(cdSize) > lim.MaxCentralDirectorySize {
		return nil, errorf(CodeZipCDBounds, "the central directory is %d bytes, over the %d byte limit", cdSize, lim.MaxCentralDirectorySize)
	}
	cd, err := readAt(r, int64(cdOffset), int64(cdSize))
	if err != nil {
		return nil, err
	}

	z := &zipFile{r: r, byName: make(map[string]Entry, entriesTotal)}
	spans := make([]span, 0, entriesTotal)
	pos := 0
	for i := 0; i < int(entriesTotal); i++ {
		if len(cd)-pos < cdRecordSize {
			return nil, errorf(CodeZipCDEntry, "central directory record %d overruns the central directory", i)
		}
		rec := cd[pos:]
		if binary.LittleEndian.Uint32(rec) != sigCentralDirectory {
			return nil, errorf(CodeZipCDEntry, "central directory record %d has a bad signature", i)
		}
		flags := binary.LittleEndian.Uint16(rec[8:])
		method := binary.LittleEndian.Uint16(rec[10:])
		crc := binary.LittleEndian.Uint32(rec[16:])
		compSize := binary.LittleEndian.Uint32(rec[20:])
		uncompSize := binary.LittleEndian.Uint32(rec[24:])
		nameLen := int(binary.LittleEndian.Uint16(rec[28:]))
		extraLen := int(binary.LittleEndian.Uint16(rec[30:]))
		commentLen := int(binary.LittleEndian.Uint16(rec[32:]))
		diskStart := binary.LittleEndian.Uint16(rec[34:])
		localOffset := binary.LittleEndian.Uint32(rec[42:])
		recordLen := cdRecordSize + nameLen + extraLen + commentLen
		if len(cd)-pos < recordLen {
			return nil, errorf(CodeZipCDEntry, "central directory record %d overruns the central directory", i)
		}
		nameBytes := rec[cdRecordSize : cdRecordSize+nameLen]
		extra := rec[cdRecordSize+nameLen : cdRecordSize+nameLen+extraLen]
		name, nerr := validName(nameBytes, lim.MaxNameLength)
		if nerr != nil {
			return nil, nerr
		}
		if diskStart != 0 {
			return nil, errorf(CodeZipMultiDisk, "entry %s starts on disk %d", axml.Quote(name), diskStart)
		}
		if compSize == 0xffffffff || uncompSize == 0xffffffff || localOffset == 0xffffffff {
			return nil, errorf(CodeZip64Unsupported, "entry %s uses zip64 sentinels", axml.Quote(name))
		}
		if err := checkExtra(extra, name); err != nil {
			return nil, err
		}
		if flags&(flagEncrypted|flagStrongEncrypted|flagMaskedHeaders) != 0 {
			return nil, errorf(CodeZipEncrypted, "entry %s is encrypted", axml.Quote(name))
		}
		switch method {
		case methodStored:
			if compSize != uncompSize {
				return nil, errorf(CodeZipMethodUnsupported, "stored entry %s has different compressed and uncompressed sizes", axml.Quote(name))
			}
		case methodDeflate:
		default:
			return nil, errorf(CodeZipMethodUnsupported, "entry %s uses compression method %d", axml.Quote(name), method)
		}
		if _, dup := z.byName[name]; dup {
			return nil, errorf(CodeZipDuplicateEntry, "entry %s appears more than once", axml.Quote(name))
		}
		e := Entry{
			Name: name, Method: method, Flags: flags, CRC32: crc,
			CompressedSize: int64(compSize), UncompressedSize: int64(uncompSize),
			LocalHeaderOffset: int64(localOffset),
		}
		end, err := z.checkLocalHeader(&e, nameBytes, int64(cdOffset))
		if err != nil {
			return nil, err
		}
		spans = append(spans, span{name: name, start: e.LocalHeaderOffset, end: end})
		z.entries = append(z.entries, e)
		z.byName[name] = e
		pos += recordLen
	}
	if pos != len(cd) {
		return nil, errorf(CodeZipCDBounds, "the central directory has %d unexplained trailing bytes", len(cd)-pos)
	}
	if err := z.checkLayout(spans, int64(cdOffset)); err != nil {
		return nil, err
	}
	return z, nil
}

// validName：UTF-8、无控制字符、无反斜杠、不以 / 开头、没有空段与 . .. 段。
func validName(raw []byte, maxLen int) (string, *Error) {
	if len(raw) == 0 {
		return "", errorf(CodeZipNameInvalid, "an entry has an empty name")
	}
	if len(raw) > maxLen {
		return "", errorf(CodeZipNameInvalid, "an entry name is %d bytes, over the %d limit", len(raw), maxLen)
	}
	if !utf8.Valid(raw) {
		return "", errorf(CodeZipNameInvalid, "entry name %s is not valid UTF-8", axml.Quote(string(raw)))
	}
	name := string(raw)
	for _, r := range name {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return "", errorf(CodeZipNameInvalid, "entry name %s contains a control character", axml.Quote(name))
		}
	}
	if strings.ContainsRune(name, '\\') || strings.HasPrefix(name, "/") {
		return "", errorf(CodeZipNameInvalid, "entry name %s is not a clean relative path", axml.Quote(name))
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", errorf(CodeZipNameInvalid, "entry name %s is not a clean relative path", axml.Quote(name))
		}
	}
	return name, nil
}

func checkExtra(extra []byte, name string) *Error {
	for len(extra) > 0 {
		if len(extra) < 4 {
			return errorf(CodeZipCDEntry, "entry %s has a truncated extra field", axml.Quote(name))
		}
		id := binary.LittleEndian.Uint16(extra)
		n := int(binary.LittleEndian.Uint16(extra[2:]))
		if len(extra)-4 < n {
			return errorf(CodeZipCDEntry, "entry %s has a truncated extra field", axml.Quote(name))
		}
		if id == extraZip64 {
			return errorf(CodeZip64Unsupported, "entry %s has a zip64 extra field", axml.Quote(name))
		}
		extra = extra[4+n:]
	}
	return nil
}

// checkLocalHeader 核对本地头与中央目录一致，填好 DataOffset，返回条目占用区间的结束位置。
func (z *zipFile) checkLocalHeader(e *Entry, nameBytes []byte, cdOffset int64) (int64, error) {
	name := axml.Quote(e.Name)
	if e.LocalHeaderOffset+localHeaderSize > cdOffset {
		return 0, errorf(CodeZipLocalHeaderMismatch, "entry %s local header lies outside the entry area", name)
	}
	lh, err := readAt(z.r, e.LocalHeaderOffset, localHeaderSize)
	if err != nil {
		return 0, err
	}
	if binary.LittleEndian.Uint32(lh) != sigLocalHeader {
		return 0, errorf(CodeZipLocalHeaderMismatch, "entry %s has no local header at offset %d", name, e.LocalHeaderOffset)
	}
	flags := binary.LittleEndian.Uint16(lh[6:])
	method := binary.LittleEndian.Uint16(lh[8:])
	crc := binary.LittleEndian.Uint32(lh[14:])
	compSize := binary.LittleEndian.Uint32(lh[18:])
	uncompSize := binary.LittleEndian.Uint32(lh[22:])
	nameLen := int64(binary.LittleEndian.Uint16(lh[26:]))
	extraLen := int64(binary.LittleEndian.Uint16(lh[28:]))
	if flags != e.Flags || method != e.Method {
		return 0, errorf(CodeZipLocalHeaderMismatch, "entry %s local header flags or method differ from the central directory", name)
	}
	if nameLen != int64(len(nameBytes)) || e.LocalHeaderOffset+localHeaderSize+nameLen+extraLen > cdOffset {
		return 0, errorf(CodeZipLocalHeaderMismatch, "entry %s local header name differs from the central directory", name)
	}
	localName, err := readAt(z.r, e.LocalHeaderOffset+localHeaderSize, nameLen)
	if err != nil {
		return 0, err
	}
	if !bytes.Equal(localName, nameBytes) {
		return 0, errorf(CodeZipLocalHeaderMismatch, "entry %s local header name differs from the central directory", name)
	}
	e.DataOffset = e.LocalHeaderOffset + localHeaderSize + nameLen + extraLen
	end := e.DataOffset + e.CompressedSize
	if end > cdOffset {
		return 0, errorf(CodeZipOverlap, "entry %s data runs into the central directory", name)
	}
	if flags&flagDataDescriptor == 0 {
		if crc != e.CRC32 || int64(compSize) != e.CompressedSize || int64(uncompSize) != e.UncompressedSize {
			return 0, errorf(CodeZipLocalHeaderMismatch, "entry %s local header CRC or sizes differ from the central directory", name)
		}
		return end, nil
	}
	// 有数据描述符：本地头里的值要么是 0，要么与中央目录一致；描述符必须与中央目录一致
	if (crc != 0 && crc != e.CRC32) || (compSize != 0 && int64(compSize) != e.CompressedSize) || (uncompSize != 0 && int64(uncompSize) != e.UncompressedSize) {
		return 0, errorf(CodeZipLocalHeaderMismatch, "entry %s local header CRC or sizes differ from the central directory", name)
	}
	if end+12 > cdOffset {
		return 0, errorf(CodeZipOverlap, "entry %s data descriptor runs into the central directory", name)
	}
	matches := func(fields []byte) bool {
		return binary.LittleEndian.Uint32(fields) == e.CRC32 && int64(binary.LittleEndian.Uint32(fields[4:])) == e.CompressedSize &&
			int64(binary.LittleEndian.Uint32(fields[8:])) == e.UncompressedSize
	}
	// 描述符可以带也可以不带 0x08074b50 签名；先按带签名的 16 字节读
	if end+16 <= cdOffset {
		desc, err := readAt(z.r, end, 16)
		if err != nil {
			return 0, err
		}
		if binary.LittleEndian.Uint32(desc) == sigDataDescriptor && matches(desc[4:]) {
			return end + 16, nil
		}
	}
	desc, err := readAt(z.r, end, 12)
	if err != nil {
		return 0, err
	}
	if !matches(desc) {
		return 0, errorf(CodeZipLocalHeaderMismatch, "entry %s data descriptor differs from the central directory", name)
	}
	return end + 12, nil
}

// span 是一个条目占用的区间：[本地头, 数据结束或数据描述符结束)。
type span struct {
	name       string
	start, end int64
}

// checkLayout：条目按本地头偏移排好后首尾相接，从 0 开始；最后一个条目与中央目录之间
// 只允许恰好一个格式正确的 APK Signing Block。
func (z *zipFile) checkLayout(spans []span, cdOffset int64) error {
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	pos := int64(0)
	for i, s := range spans {
		if s.start < pos {
			return errorf(CodeZipOverlap, "entry %s overlaps the previous entry", axml.Quote(s.name))
		}
		if s.start > pos {
			if i == 0 {
				return errorf(CodeZipUnaccountedBytes, "%d bytes precede the first entry", s.start)
			}
			return errorf(CodeZipUnaccountedBytes, "%d bytes between entries are not part of any entry (before %s)", s.start-pos, axml.Quote(s.name))
		}
		pos = s.end
	}
	gap := cdOffset - pos
	if gap == 0 {
		return nil
	}
	if gap < signingBlockMinSize {
		return errorf(CodeZipUnaccountedBytes, "%d bytes before the central directory are not part of any entry", gap)
	}
	unaccounted := errorf(CodeZipUnaccountedBytes, "%d bytes before the central directory are not part of any entry", gap)
	foot, err := readAt(z.r, cdOffset-24, 24)
	if err != nil {
		return err
	}
	sizeEnd := binary.LittleEndian.Uint64(foot)
	if string(foot[8:]) != signingBlockMagic || sizeEnd > uint64(gap-8) {
		return unaccounted
	}
	blockStart := cdOffset - int64(sizeEnd) - 8
	head, err := readAt(z.r, blockStart, 8)
	if err != nil {
		return err
	}
	if binary.LittleEndian.Uint64(head) != sizeEnd {
		return unaccounted
	}
	// apksigner 在签名块前补零，让块从 4096 字节边界开始（给 APK verity 用）。只接受这种填充：
	// 全是零、不足一页、块恰好落在页边界上。
	if padding := blockStart - pos; padding > 0 {
		if padding >= signingBlockPageSize || blockStart%signingBlockPageSize != 0 {
			return unaccounted
		}
		zeros, err := readAt(z.r, pos, padding)
		if err != nil {
			return err
		}
		for _, b := range zeros {
			if b != 0 {
				return unaccounted
			}
		}
	}
	z.signingBlock = true
	return nil
}

// read 解压一个条目，限制解压大小并校验长度与 CRC。
func (z *zipFile) read(e Entry, limit int64) ([]byte, error) {
	if e.UncompressedSize > limit {
		return nil, errorf(CodeZipEntryTooLarge, "entry %s declares %d bytes, over the %d byte limit", axml.Quote(e.Name), e.UncompressedSize, limit)
	}
	section := io.NewSectionReader(z.r, e.DataOffset, e.CompressedSize)
	var src io.Reader = section
	if e.Method == methodDeflate {
		fr := flate.NewReader(section)
		defer fr.Close()
		src = fr
	}
	var buf bytes.Buffer
	n, err := io.Copy(&buf, io.LimitReader(src, e.UncompressedSize+1))
	if err != nil {
		return nil, errorf(CodeZipEntryCorrupt, "entry %s cannot be decompressed: %v", axml.Quote(e.Name), err)
	}
	if n != e.UncompressedSize {
		return nil, errorf(CodeZipEntryCorrupt, "entry %s decompresses to a different size than declared", axml.Quote(e.Name))
	}
	if crc32.ChecksumIEEE(buf.Bytes()) != e.CRC32 {
		return nil, errorf(CodeZipEntryCorrupt, "entry %s fails its CRC check", axml.Quote(e.Name))
	}
	return buf.Bytes(), nil
}

// v1SignatureFiles 找 META-INF/ 下直接的 JAR 签名文件。
func v1SignatureFiles(entries []Entry) []string {
	var out []string
	for _, e := range entries {
		rest, ok := strings.CutPrefix(e.Name, "META-INF/")
		if !ok || strings.Contains(rest, "/") {
			continue
		}
		upper := strings.ToUpper(rest)
		if strings.HasSuffix(upper, ".SF") || strings.HasSuffix(upper, ".RSA") || strings.HasSuffix(upper, ".DSA") ||
			strings.HasSuffix(upper, ".EC") || strings.HasPrefix(upper, "SIG-") {
			out = append(out, e.Name)
		}
	}
	return out
}

// misaligned 按 zipalign -c -P 16 4 检查：STORED 条目数据 4 字节对齐，.so 按 16 KiB 页对齐。
func misaligned(entries []Entry) ([]Misaligned, int) {
	var out []Misaligned
	count := 0
	for _, e := range entries {
		if e.Method != methodStored {
			continue
		}
		align := int64(storedAlignment)
		if strings.HasSuffix(e.Name, ".so") {
			align = pageAlignment
		}
		if e.DataOffset%align != 0 {
			count++
			if len(out) < maxMisalignedListed {
				out = append(out, Misaligned{Name: e.Name, DataOffset: e.DataOffset, Alignment: align})
			}
		}
	}
	return out, count
}
