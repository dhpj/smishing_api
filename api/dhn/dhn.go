package dhn

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"runtime/debug"
	"time"
	"strings"

	ss "mycs/api/smishing"
	uc "mycs/api/urichecker"
	"mycs/configs"
	"mycs/configs/databasepool"

	"github.com/caddyserver/certmagic"
	"github.com/fasthttp/router"
	"github.com/valyala/fasthttp"
)

const (
	certEmail   = "dhn@dhncorp.co.kr"
)

// 💡 KISA 스미싱 API 응답 구조체
type KisaSmishingRes struct {
	ResCode  int    `json:"resCode"`
	ResMsg   string `json:"resMsg"`
	ResDatas []struct {
		RecvUrl  string `json:"recvUrl"`
		SmStatus string `json:"smStatus"` // "스미싱", "안전", "판정 취소"
	} `json:"resDatas"`
}

func DhnProc() {
	configs.Stdlog.Println("=== 통합 API 시스템 구동 시작 ===")

	go GoogleProc()

	go SmishingProc()
	// 🚀 KISA 비동기 수집 엔진 스레드 출발
	go KisaSmishingCollector()

}

func GoogleProc() {
	r := router.New()

	r.GET("/", func(c *fasthttp.RequestCtx) {
		c.SetStatusCode(fasthttp.StatusOK)
		c.SetBodyString("Google API 정상 수신 완료\n")
	})

	r.POST("/check_uri", authMiddleware(uc.CheckUri))

	topLevelHandler := recoveryMiddleware(r.Handler)

	//특정포트 시작
	server1 := &fasthttp.Server{
		Handler: topLevelHandler,
		MaxRequestBodySize: 20 * 1024 * 1024,
	}
	configs.Stdlog.Println("GoogleProc 실행 포트 : " + configs.Conf.PORT)
	go func(){
		if err := server1.ListenAndServe(":" + configs.Conf.PORT); err != nil {
			configs.Stdlog.Println("GoogleProc 실행 실패")
		}
	}()
	//특정포트 끝

	// 80포트 실행
	// go func() {
	//     config.Stdlog.Println("fasthttp 실행 포트 : 80")
	//     if err := fasthttp.ListenAndServe(":80", topLevelHandler); err != nil {
	//         config.Stdlog.Println("fasthttp 80 실행 실패:", err)
	//     }
	// }()
}

func SmishingProc() {
	r := router.New()

	r.GET("/", func(c *fasthttp.RequestCtx) {
		c.SetStatusCode(fasthttp.StatusOK)
		c.SetBodyString("Smishing API 정상 수신 완료\n")
	})

	r.POST("/check_uri", authMiddleware2(ss.CheckUri))

	r.POST("/set_userid", ss.SetUserid)

	r.POST("/get_ad_img", authMiddleware2(ss.GetAdImg))

	// 스미싱 전용 미들웨어 체이닝 (인증 등 필요하면 여기에 추가)
	topLevelHandler := recoveryMiddleware(r.Handler)

	server := &fasthttp.Server{
		Handler:            topLevelHandler,
		MaxRequestBodySize: 20 * 1024 * 1024,
	}


	configs.Stdlog.Println("SmishingProc 실행 포트 : " + configs.Conf.PORT2)
	go func() {
		if err := server.ListenAndServe(":" + configs.Conf.PORT2); err != nil {
			configs.Stdlog.Println("SmishingProc 실행 실패:", err)
		}
	}()

	if configs.Conf.SSL_FLAG == "Y" {
		//SSL 시작
		certmagic.DefaultACME.Agreed = true
		certmagic.DefaultACME.Email = certEmail
		certmagic.DefaultACME.CA = certmagic.LetsEncryptProductionCA

		err := certmagic.ManageSync(context.TODO(), []string{configs.Conf.DNS})

		if err != nil {
			configs.Stdlog.Println("certmagic.ManageSync 에러 : ", err)
			log.Fatal("certmagic.ManageSync 에러 : ", err)
		} else {
			configs.Stdlog.Println("certmagic.ManageSync 성공 인증서 자동갱신 시작")
		}

		certmagicCfg := certmagic.NewDefault()
		tlsConfig := certmagicCfg.TLSConfig()

		tlsConfig.MinVersion = tls.VersionTLS12

		tlsConfig.CipherSuites = []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		}

		tlsConfig.NextProtos = []string{"h2", "http/1.1"}


		server2 := &fasthttp.Server{
			Handler: topLevelHandler,
			MaxRequestBodySize: 20 * 1024 * 1024,
			TLSConfig: tlsConfig,
		}

		configs.Stdlog.Println("fasthttp 실행 포트 : " + configs.Conf.SSL_PORT)
		go func() {
			if err := server2.ListenAndServeTLS(":" + configs.Conf.SSL_PORT, "", ""); err != nil {
				configs.Stdlog.Println("fasthttp 실행 실패")
			}
		}()
		//SSL 끝
	}
}

func recoveryMiddleware(next fasthttp.RequestHandler) fasthttp.RequestHandler {
    return func(c *fasthttp.RequestCtx) {
        defer func() {
            if r := recover(); r != nil {
                // panic 로그 기록
                configs.Stdlog.Println("Recovered from panic : ", r)
                configs.Stdlog.Println("Stack trace: ", string(debug.Stack()))
            }
        }()
        next(c) // 다음 미들웨어 또는 핸들러로 넘김
    }
}

func authMiddleware(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(c *fasthttp.RequestCtx){
		userId := string(c.Request.Header.Peek("userid"))
		userIp := c.RemoteIP().String()
		path := string(c.Path())
		
		configs.Stdlog.Println("Google API 요청 path :", path, " / id:" + userId + " / ip :", userIp)

		var cnt sql.NullInt16
		databasepool.DB.QueryRow("select count(1) cnt from DHN_CLIENT_LIST where userid = ? and ip = ?", userId, userIp).Scan(&cnt)

		if cnt.Valid && cnt.Int16 > 0 {
			databasepool.DB.Exec("insert into CALL_API(userid, ip, path) values (?, ?, ?)", userId, userIp, path)
			next(c)
		} else {
			configs.Stdlog.Println("인가되지 않은 사용자 요청 id:" + userId + " / ip :", userIp)
			res := make(map[string]interface{})
			res["code"] = "1001"
			res["message"] = "허용되지 않은 아이디 및 아이피 입니다."
			bytes, _ := json.Marshal(res)

			c.SetStatusCode(fasthttp.StatusOK)
			c.SetContentType("application/json")
			c.SetBody(bytes)
		}

	}
}

func authMiddleware2(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(c *fasthttp.RequestCtx){
		userId := string(c.Request.Header.Peek("userid"))
		userIp := c.RemoteIP().String()
		path := string(c.Path())
		
		configs.Stdlog.Println("Smishing API 요청 path :", path, " / id:" + userId + " / ip :", userIp)

		var cnt sql.NullInt16
		databasepool.DB2.QueryRow("select count(1) cnt from DHN_CLIENT_LIST where userid = ?", userId).Scan(&cnt)

		if cnt.Valid && cnt.Int16 > 0 {
			next(c)
		} else {
			configs.Stdlog.Println("인가되지 않은 사용자 요청 id:" + userId + " / ip :", userIp)
			res := make(map[string]interface{})
			res["code"] = "1001"
			res["message"] = "허용되지 않은 아이디입니다."
			bytes, _ := json.Marshal(res)

			c.SetStatusCode(fasthttp.StatusForbidden)
			c.SetContentType("application/json")
			c.SetBody(bytes)
		}

	}
}

// 💡 1. 백그라운드에서 주기적으로 도는 스케줄러 고루틴
func KisaSmishingCollector() {
	configs.Stdlog.Println("KISA 스미싱 정보 수집 스케줄러 시작")
	
	// 💡 1시간 주기로 변경 완료!
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	// 서버가 실행되자마자 1회 긁어오기
	fetchKisaSmishing()

	for {
		<-ticker.C
		fetchKisaSmishing()
	}
}

// 💡 2. 실제 KISA API를 호출하고 페이징 처리하는 워커
func fetchKisaSmishing() {
	configs.Stdlog.Println("KISA 스미싱 정보 수집 시작")
	// 🚨 형님의 configs 세팅에 URL과 토큰 추가 필요
	apiUrl := configs.Conf.KISA_SMISHING_URL 
	token := configs.Conf.KISA_API_TOKEN

	client := &http.Client{Timeout: 30 * time.Second}

	for {
		// stime 생략을 위해 빈 맵 전송 (마지막 조회 이후 데이터 자동 수신)
		reqBody := map[string]interface{}{}
		bodyBytes, _ := json.Marshal(reqBody)

		req, err := http.NewRequest("POST", apiUrl, bytes.NewBuffer(bodyBytes))
		if err != nil {
			configs.Stdlog.Println("KISA Request 생성 에러:", err)
			break
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := client.Do(req)
		if err != nil {
			configs.Stdlog.Println("KISA API 통신 에러:", err)
			break
		}

		if resp.StatusCode != http.StatusOK {
			configs.Stdlog.Println("KISA API 상태코드 에러:", resp.StatusCode)
			resp.Body.Close()
			break
		}

		var kisaRes KisaSmishingRes
		if err := json.NewDecoder(resp.Body).Decode(&kisaRes); err != nil {
			configs.Stdlog.Println("KISA JSON 디코딩 에러:", err)
			resp.Body.Close()
			break
		}
		resp.Body.Close()

		if kisaRes.ResCode != 0 {
			configs.Stdlog.Printf("KISA API 응답 에러 (코드: %d, 메시지: %s)\n", kisaRes.ResCode, kisaRes.ResMsg)
			break
		}

		count := len(kisaRes.ResDatas)
		if count > 0 {
			// 🚀 DB Bulk Upsert (수집된 URL 1000건을 한방 쿼리로 밀어넣기)
			var queryBuilder strings.Builder
			queryBuilder.WriteString("INSERT INTO WEB_RISK (uri, status) VALUES ")
			
			var values []interface{}
			var placeholders []string
			
			for _, data := range kisaRes.ResDatas {
				// 기본값 0(정상/판정 취소), "스미싱"일 경우만 1
				status := 0 
				if data.SmStatus == "스미싱" {
					status = 1
				}
				
				placeholders = append(placeholders, "(?, ?)")
				values = append(values, data.RecvUrl, status)
			}
			
			queryBuilder.WriteString(strings.Join(placeholders, ","))
			// uri가 이미 존재하면 status 값만 최신으로 덮어쓰기
			queryBuilder.WriteString(" ON DUPLICATE KEY UPDATE status = VALUES(status)")
			
			_, err := databasepool.DB.Exec(queryBuilder.String(), values...)
			if err != nil {
				configs.Stdlog.Println("KISA DB 적재 에러:", err)
			} else {
				configs.Stdlog.Printf("KISA 데이터 %d건 DB 적재/갱신 완료 (첫 URL: %s)", count, kisaRes.ResDatas[0].RecvUrl)
			}
		}

		// 💡 핵심 로직: 반환 데이터가 1,000건이면 다음 페이지가 무조건 있다는 뜻
		if count == 1000 {
			configs.Stdlog.Println("KISA 스미싱 데이터 1,000건 초과. 다음 페이지 연속 조회 진행...")
			time.Sleep(500 * time.Millisecond) // API 서버 보호용 짧은 대기 후 루프 이어서 진행 (continue)
			continue
		} else {
			// 1,000건 미만이면 남은 데이터가 없으므로 루프 탈출 (다음 Ticker 주기까지 대기)
			break
		}
	}
	configs.Stdlog.Println("KISA 스미싱 정보 수집 끋")
}