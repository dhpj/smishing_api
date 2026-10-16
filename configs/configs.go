package configs

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	ini "github.com/BurntSushi/toml"
	rotatelogs "github.com/lestrrat/go-file-rotatelogs"
)

type Config struct {
	DNS                string
	SSL_FLAG           string
	SSL_PORT           string

	PORT               string
	PORT2              string
	
	DB                 string
	DBURL              string
	DB2                string
	DBURL2             string

	WEB_RISK_FILE_NAME string

	// 🚀 기존 DB 설정을 망가뜨리지 않기 위해 string 원상복구 후 태그 제거!
	URLSCAN_API_KEY    string 

	GEMINI_API_KEY     string

	KISA_SMISHING_URL  string
	KISA_API_TOKEN     string
}

var (
	Conf      Config
	Stdlog    *log.Logger
	Errlog    *log.Logger
	IsRunning bool = true

	LastKeyIdx uint32
)

func InitConfig() {
	realpath, _ := os.Executable()
	dir := filepath.Dir(realpath)
	Conf = readConfig()
	logDir := filepath.Join(dir, "logs")
	path := filepath.Join(logDir, "DHNApi")

	loc, _ := time.LoadLocation("Asia/Seoul")
	writer, err := rotatelogs.New(
		fmt.Sprintf("%s-%s.log", path, "%Y-%m-%d"),
		rotatelogs.WithLocation(loc),
		rotatelogs.WithMaxAge(-1),
		rotatelogs.WithRotationCount(7),
	)

	if err != nil {
		log.Fatalf("Failed to Initialize Log File %s", err)
	}

	log.SetOutput(writer)
	stdlog := log.New(os.Stdout, "INFO -> ", log.Ldate|log.Ltime)
	stdlog.SetOutput(writer)
	Stdlog = stdlog
}

func readConfig() Config {
	realpath, _ := os.Executable()
	dir := filepath.Dir(realpath)
	var configfile = filepath.Join(dir, "config.ini")
	_, err := os.Stat(configfile)
	if err != nil {
		system_exit("DHNApi")
		fmt.Println("Config file is missing : ", configfile)
	}

	var result Config
	_, err1 := ini.DecodeFile(configfile, &result)

	if err1 != nil {
		fmt.Println("Config file read error : ", err1)
	}

	return result
}

func system_exit(service_name string) {
	cmd := exec.Command("systemctl", "stop", service_name)
	if err := cmd.Run(); err != nil {
		Stdlog.Println(service_name+" 서비스 종료 실패:", err)
	} else {
		Stdlog.Println(service_name + " 서비스가 성공적으로 종료되었습니다.")
	}
}

// 🚀 [라운드 로빈] 콤마로 연결된 문자열을 실시간 분리해서 순환 추출하는 스마트 로테이터
func GetActiveUrlScanKey() string {
	rawKeys := Conf.URLSCAN_API_KEY
	if rawKeys == "" || strings.TrimSpace(rawKeys) == "" {
		return ""
	}

	// 콤마(,) 기준으로 문자열을 잘라 슬라이스 배열 생성
	keys := strings.Split(rawKeys, ",")
	keysCount := len(keys)
	if keysCount == 0 {
		return ""
	}

	// 원자적 인덱스 연산으로 라운드 로빈 순환
	idx := atomic.AddUint32(&LastKeyIdx, 1)
	targetIdx := int(idx) % keysCount

	// 양끝 공백 확실히 제거 후 안전하게 키 반환
	return strings.TrimSpace(keys[targetIdx])
}