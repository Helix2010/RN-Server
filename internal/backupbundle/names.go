package backupbundle

import (
	"fmt"
	"time"
)

// PackageBaseName 是一组备份在桶里的文件名，不带扩展名。
//
// 带上产出时间：编号是数据库自增的，换一个数据库（另一套环境共用这个桶、数据库重建
// 之后）编号就从 1 重来。只靠编号的话，两份备份会拿到同一个名字，后写的覆盖先写的
// ——桶没开版本控制时，被覆盖的那份就没了。时间放在编号前面，桶里按名字排就是按
// 时间排。
//
// 上传用的对象键和 README-FIRST 里印的名字都从这里出。两处各拼一份的话，README 上
// 写的「另外两个包」在桶里就找不到。
func PackageBaseName(seq uint64, createdAt time.Time, pair string) string {
	return fmt.Sprintf("backup-%s-%08d-%s", createdAt.UTC().Format("20060102T150405Z"), seq, pair)
}
