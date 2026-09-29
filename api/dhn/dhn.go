package dhn

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"log"
	"runtime/debug"

	uc "mycs/api/urichecker"
	ss "mycs/api/smishing"
	"mycs/configs"
	"mycs/configs/databasepool"

	"github.com/caddyserver/certmagic"
	"github.com/fasthttp/router"
	"github.com/valyala/fasthttp"
)

const (
	certEmail   = "dhn@dhncorp.co.kr"
)

func DhnProc() {
	configs.Stdlog.Println("=== 통합 API 시스템 구동 시작 ===")

	go GoogleProc()

	go SmishingProc()
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