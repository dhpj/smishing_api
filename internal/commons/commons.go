package commons

import (
	"crypto/rand"
	"mycs/configs"
)

const base62Chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func GenerateRandomString(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		// 혹시라도 난수 생성 실패 시 기본값 처리 (실제론 거의 안 일어남)
		configs.Errlog.Println("난수 생성 실패:", err)
		return ""
	}
	for i := 0; i < length; i++ {
		// 생성된 난수 바이트를 62로 나눈 나머지 값으로 인덱스 매핑
		b[i] = base62Chars[b[i]%62]
	}
	return string(b)
}