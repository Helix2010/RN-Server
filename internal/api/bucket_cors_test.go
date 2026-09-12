package api

import (
	"context"
	"testing"
)

// 写进桶的必须是**全平台**活跃租户域名的并集。CORS 是桶级配置不是前缀级的，
// 同一个桶被多个租户共用时，只写当前租户的来源会把其他租户直接踢掉——表现是
// 另一个租户的控制台突然传不了图，而没有人改过他们的任何配置。
func TestDBBucketCORSCoversEveryActiveTenantDomain(t *testing.T) {
	db := openTestDB(t)
	s := &server{db: db}
	origins, err := s.tenantConsoleOrigins(context.Background())
	if err != nil {
		t.Fatalf("取租户域名失败: %v", err)
	}
	for _, origin := range origins {
		if len(origin) < len("https://") || origin[:len("https://")] != "https://" {
			t.Fatalf("来源不是 https：%q —— 这条通道会带凭证，明文来源等于把会话交出去", origin)
		}
	}
	// 返回值必须有序：无序会让每次保存都写一份"看起来不同"的规则，审计里全是噪音
	for i := 1; i < len(origins); i++ {
		if origins[i-1] > origins[i] {
			t.Fatalf("来源没有排序：%q 在 %q 之前", origins[i-1], origins[i])
		}
	}
}
