package urichecker

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"mycs/configs"
	"mycs/configs/databasepool"

	webrisk "cloud.google.com/go/webrisk/apiv1"
	pb "cloud.google.com/go/webrisk/apiv1/webriskpb"
	"github.com/valyala/fasthttp"
	"google.golang.org/api/option"
)

// 💡 1. urlscan.io POST Submission 응답 구조체
type UrlScanSubmitResponse struct {
	Message    string `json:"message"`
	UUID       string `json:"uuid"`
	Result     string `json:"result"`
	API        string `json:"api"`
	Visibility string `json:"visibility"`
}

// 💡 2. urlscan.io GET Result 최종 결과 판별용 임시 구조체
type UrlScanResultResponse struct {
	Verdicts struct {
		Overall struct {
			Score     int  `json:"score"`     // 위험 스코어
			Malicious bool `json:"malicious"` // 악성 유무 여부
		} `json:"overall"`
	} `json:"verdicts"`
}

type remarks struct {
	Remark1 string
	Remark2 string
	Remark3 string
	Remark4 string
	Remark5 string
}

func CheckUri(c *fasthttp.RequestCtx) {
	type BodyData struct {
		Uri string `json:"uri"`
	}

	var responseData map[string]interface{} = map[string]interface{}{
		"code":    "0000",
		"message": "안전",
	}

	var bd BodyData
	err := json.Unmarshal(c.PostBody(), &bd)
	if err != nil {
		responseData["code"] = "1002"
		responseData["message"] = "body 데이터 json 맵핑 에러"
		configs.Stdlog.Println("Check_uri - body 데이터 json 맵핑 에러 post body :", string(c.PostBody()), " / err :", err)
		re := remarks{}
		insertErrorLog(c, responseData, re)
		respBytes, _ := json.Marshal(responseData)
		c.SetStatusCode(fasthttp.StatusInternalServerError)
		c.SetContentType("application/json")
		c.SetBody(respBytes)
		return
	}

	convUri := extractBaseDomain(bd.Uri)

	// 1단계 관문: 로컬 DB에 이미 기록된 내역이 있는지 조회
	local_res := checkLocalUri(convUri)

	if local_res == 1 { 
		respBytes, _ := json.Marshal(responseData)
		c.SetStatusCode(fasthttp.StatusOK)
		c.SetContentType("application/json")
		c.SetBody(respBytes)
		return
	} else if local_res == 0 { 
		responseData["code"] = "0001"
		responseData["message"] = "위험"
		respBytes, _ := json.Marshal(responseData)
		c.SetStatusCode(fasthttp.StatusOK)
		c.SetContentType("application/json")
		c.SetBody(respBytes)
		return
	} else {
		ctx := context.Background()

		jsonKeyPath := "/root/DHNApi/.google/webrisk/auth/" + configs.Conf.WEB_RISK_FILE_NAME

		client, err := webrisk.NewClient(ctx, option.WithCredentialsFile(jsonKeyPath))
		if err != nil {
			responseData["code"] = "1004"
			responseData["message"] = "클라이언트 생성 실패 에러"
			configs.Stdlog.Println("Check_uri - 클라이언트 생성 실패 에러 post body :", string(c.PostBody()), " / err :", err)
			re := remarks{}
			insertErrorLog(c, responseData, re)
			respBytes, _ := json.Marshal(responseData)
			c.SetStatusCode(fasthttp.StatusInternalServerError)
			c.SetContentType("application/json")
			c.SetBody(respBytes)
			return
		}
		defer client.Close()

		targetURI := convUri

		req := &pb.SearchUrisRequest{
			Uri: targetURI,
			ThreatTypes: []pb.ThreatType{
				pb.ThreatType_MALWARE,            
				pb.ThreatType_SOCIAL_ENGINEERING, 
				pb.ThreatType_UNWANTED_SOFTWARE,  
			},
		}

		resp, err := client.SearchUris(ctx, req)
		if err != nil {
			responseData["code"] = "1003"
			responseData["message"] = "Google Api 호출 에러"
			configs.Stdlog.Println("Check_uri - Google Api 호출 에러 post body :", string(c.PostBody()), " / err :", err)
			re := remarks{}
			insertErrorLog(c, responseData, re)
			respBytes, _ := json.Marshal(responseData)
			c.SetStatusCode(fasthttp.StatusInternalServerError)
			c.SetContentType("application/json")
			c.SetBody(respBytes)
			return
		}

		insertSql := "insert into WEB_RISK(uri, status) values (?, ?)"
		status := 1

		if resp.Threat != nil {
			responseData["code"] = "0001"
			responseData["message"] = "위험"
			status = 0
			databasepool.DB.Exec(insertSql, targetURI, status)

			respBytes, _ := json.Marshal(responseData)
			c.SetStatusCode(fasthttp.StatusOK)
			c.SetContentType("application/json")
			c.SetBody(respBytes)
			return
		} else {
			// 🚀 3단계 & 4단계: urlscan.io + Gemini 2.5 Flash 비동기(병렬) 동시 검사 시작!
			
			// 고루틴의 결과를 받을 채널 생성 (버퍼 크기 2로 메모리 누수 방지)
			type scanResult struct {
				isMalicious bool
				err         error
				source      string
			}
			resultCh := make(chan scanResult, 2)

			// 1. urlscan.io 검사 스레드 출발
			go func(url string) {
				malicious, err := checkUrlScanIO(url)
				resultCh <- scanResult{isMalicious: malicious, err: err, source: "urlscan"}
			}(targetURI)

			// 2. Gemini 2.5 Flash 검사 스레드 출발
			// go func(url string) {
			// 	malicious, err := checkGeminiFlash(url)
			// 	resultCh <- scanResult{isMalicious: malicious, err: err, source: "gemini"}
			// }(targetURI)

			// var urlscanMalicious, geminiMalicious bool

			var finalMalicious bool

			// 🚀 결과 수집 대기 (Fast-Fail 최적화 적용)
			for i := 0; i < 2; i++ {
				res := <-resultCh
				if res.err != nil {
					configs.Stdlog.Printf("⚠️ [%s] 비동기 검사 중 장애 발생 (임시 통과): %v", res.source, res.err)
				}
				
				if res.isMalicious {
					// 💡 Gemini나 urlscan 둘 중 하나라도 먼저 악성(true) 판정을 내리면
					// 나머지 검사 결과는 쳐다볼 필요도 없이 즉시 사형 선고 후 루프 탈출!
					finalMalicious = true
					configs.Stdlog.Printf("🚨 [%s] 악성 URL 감지! (조기 차단 가동)", res.source)
					break 
				}
			}

			// 🚀 최종 판별
			if finalMalicious {
				responseData["code"] = "0001"
				responseData["message"] = "위험"
				status = 0
			} else {
				status = 1
			}

			// 판별 결과 로컬 DB 적재 및 리턴
			databasepool.DB.Exec(insertSql, targetURI, status)

			respBytes, _ := json.Marshal(responseData)
			c.SetStatusCode(fasthttp.StatusOK)
			c.SetContentType("application/json")
			c.SetBody(respBytes)
			return
		}
	}
}

func extractBaseDomain(rawUrl string) string {
	rawUrl = strings.TrimSpace(rawUrl)

	if !strings.HasPrefix(rawUrl, "http://") && !strings.HasPrefix(rawUrl, "https://") {
		rawUrl = "http://" + rawUrl 
	}

	u, err := url.Parse(rawUrl)
	if err != nil {
		return rawUrl
	}

	u.RawQuery = ""  
	u.Fragment = ""  

	return u.String()
}

func checkUrlScanIO(targetUrl string) (bool, error) {
	var stdlog = configs.Stdlog
	var errlog = configs.Stdlog
	submitUrl := "https://urlscan.io/api/v1/scan/"

	apiKey := configs.GetActiveUrlScanKey()
	if apiKey == "" {
		return false, fmt.Errorf("설정 파일(config.ini)에 URLSCAN_API_KEY가 비어있습니다")
	}

	requestBody, _ := json.Marshal(map[string]interface{}{
		"url":        targetUrl,
		"visibility": "public",
		"tags":       []string{"raceroute_checker"},
	})

	client := &http.Client{Timeout: 15 * time.Second}

	req, err := http.NewRequest("POST", submitUrl, bytes.NewBuffer(requestBody))
	if err != nil {
		return false, fmt.Errorf("POST Request 생성 실패: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("API-Key", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("POST 서브미션 통신 에러: %v", err)
	}

	// checkUrlScanIO 함수의 POST Do(req) 바로 아랫단 구간
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyStr := string(bodyBytes)

		// 🚀 [형님의 디버깅 로그 기반 트랩 매칭] 
		// urlscan.io가 DNS 에러를 주면, 함수 자체를 에러로 터트리지 말고 "이건 악성 유령 도메인(true)"이라고 판정해서 상위로 리턴!
		if strings.Contains(bodyStr, "Could not resolve domain") {
			stdlog.Println("🚨 [urlscan.io] 연결 불가 유령 도메인 감지! 위험군(Malicious) 강제 판정 :", targetUrl)
			return true, nil // 👈 에러(err)는 nil로 주고, 악성여부(isMalicious)를 true로 넘겨버림!
		}

		return false, fmt.Errorf("POST 서브미션 거부됨 (Status: %d, Body: %s)", resp.StatusCode, bodyStr)
	}
	
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		resp.Body.Close()
		errlog.Printf("❌ [URLSCAN API 키 차단 감지] 상태코드: %d (%s), 문제의 Key 후미: ...%s", resp.StatusCode, resp.Status, apiKey[len(apiKey)-5:])
		return false, fmt.Errorf("선택된 API 키 차단됨 (%s), 로테이션 우회 필요", resp.Status)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return false, fmt.Errorf("POST 서브미션 거부됨 (Status: %d, Body: %s)", resp.StatusCode, string(bodyBytes))
	}

	var submitRes UrlScanSubmitResponse
	if err := json.NewDecoder(resp.Body).Decode(&submitRes); err != nil {
		resp.Body.Close()
		return false, fmt.Errorf("POST JSON 디코딩 에러: %v", err)
	}
	resp.Body.Close() 

	uuid := submitRes.UUID
	stdlog.Printf("🎯 [urlscan.io] 서브미션 성공 - UUID: %s (사용된 Key 후미: ...%s)", uuid, apiKey[len(apiKey)-5:])

	resultCheckUrl := fmt.Sprintf("https://urlscan.io/api/v1/result/%s/", uuid)
	maxRetries := 8 
	
	time.Sleep(5 * time.Second)

	for i := 1; i <= maxRetries; i++ {
		stdlog.Printf("🔄 [urlscan.io] 결과 조회 진행 중... (%d/%d 회 시도)", i, maxRetries)

		getReq, _ := http.NewRequest("GET", resultCheckUrl, nil)
		getReq.Header.Set("API-Key", apiKey) 

		getResp, err := client.Do(getReq)
		if err != nil {
			errlog.Println("❌ [urlscan.io] GET 통신 에러 (5초 후 다시 시도) :", err)
			time.Sleep(5 * time.Second)
			continue
		}

		statusCode := getResp.StatusCode

		if statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden || statusCode == http.StatusTooManyRequests {
			getResp.Body.Close()
			errlog.Printf("❌ [URLSCAN API 키 차단 감지] 상태코드: %d (%s), 문제의 Key 후미: ...%s", statusCode, getResp.Status, apiKey[len(apiKey)-5:])
			return false, fmt.Errorf("결과 조회 도중 API 키 차단 상태 확인됨 (%s)", getResp.Status)
		}

		if statusCode == http.StatusNotFound {
			getResp.Body.Close() 
			time.Sleep(5 * time.Second)
			continue
		}

		if statusCode == http.StatusOK {
			var scanResult UrlScanResultResponse
			if err := json.NewDecoder(getResp.Body).Decode(&scanResult); err != nil {
				getResp.Body.Close()
				return false, fmt.Errorf("GET 결과 JSON 파싱 실패: %v", err)
			}
			getResp.Body.Close() 

			isMalicious := scanResult.Verdicts.Overall.Malicious
			stdlog.Printf("✅ [urlscan.io] 최종 스캔 완료! - 악성여부: %t, 위험점수: %d", isMalicious, scanResult.Verdicts.Overall.Score)
			
			return isMalicious, nil
		}

		bodyBytes, _ := io.ReadAll(getResp.Body)
		getResp.Body.Close() 
		errlog.Printf("⚠️ [urlscan.io] 예상치 못한 상태 코드 (Status: %d, Body: %s)", statusCode, string(bodyBytes))
		time.Sleep(5 * time.Second)
	}

	return false, fmt.Errorf("❌ [urlscan.io] Timeout 실패: 40초 초과 (UUID: %s)", uuid)
}

func insertErrorLog(c *fasthttp.RequestCtx, responseData map[string]interface{}, remarks remarks){
	userId := string(c.Request.Header.Peek("userid"))
	userIp := c.RemoteIP().String()
	path := string(c.Path())
	code := responseData["code"]
	message := responseData["message"]
	databasepool.DB.Exec("insert into FAIL_LOG(userid, ip, path, code, message, remark1, remark2, remark3, remark4, remark5) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		userId, userIp, path, code, message, remarks.Remark1, remarks.Remark2, remarks.Remark3, remarks.Remark4, remarks.Remark5)
}

func checkLocalUri(uri string) int {
	var status sql.NullInt16
	databasepool.DB.QueryRow("select status from WEB_RISK where uri = ?", uri).Scan(&status)

	if status.Valid {
		return int(status.Int16) 
	} else {
		return 2 
	}
} // 🚀 [교정] 무너졌던 중괄호 스코프 완전 마감 처리 완료!

// 💡 4단계: Gemini 2.5 Flash AI 정밀 추론
// func checkGeminiFlash(targetUrl string) (bool, error) {
// 	var stdlog = configs.Stdlog
// 	var errlog = configs.Stdlog

// 	// 🚨 형님 환경의 config.ini 등에 GEMINI_API_KEY를 추가해 주십쇼
// 	apiKey := configs.Conf.GEMINI_API_KEY
// 	if apiKey == "" {
// 		return false, fmt.Errorf("설정 파일에 GEMINI_API_KEY가 없습니다")
// 	}

// 	apiUrl := "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=" + apiKey

// 	// 프롬프트: 스미싱/피싱 여부를 판단하고 무조건 JSON 형태로만 응답하도록 강제
// 	prompt := fmt.Sprintf(`Analyze this URL for smishing, phishing, or malicious intent: "%s".
// 	Consider URL shortening, obfuscation, brand spoofing, and suspicious TLDs.
// 	Respond STRICTLY in valid JSON format with exactly two keys:
// 	"malicious": boolean (true if malicious/suspicious, false if safe),
// 	"reason": string (brief explanation)`, targetUrl)

// 	reqBody := map[string]interface{}{
// 		"contents": []map[string]interface{}{
// 			{
// 				"parts": []map[string]interface{}{
// 					{"text": prompt},
// 				},
// 			},
// 		},
// 		// 🚀 JSON 응답 강제 옵션 (파싱 에러 원천 차단)
// 		"generationConfig": map[string]interface{}{
// 			"responseMimeType": "application/json",
// 		},
// 	}

// 	bodyBytes, _ := json.Marshal(reqBody)
// 	client := &http.Client{Timeout: 10 * time.Second} // Flash 모델이므로 10초면 매우 넉넉함

// 	req, err := http.NewRequest("POST", apiUrl, bytes.NewBuffer(bodyBytes))
// 	if err != nil {
// 		return false, fmt.Errorf("Gemini POST Request 생성 실패: %v", err)
// 	}
// 	req.Header.Set("Content-Type", "application/json")

// 	resp, err := client.Do(req)
// 	if err != nil {
// 		return false, fmt.Errorf("Gemini API 통신 에러: %v", err)
// 	}
// 	defer resp.Body.Close()

// 	if resp.StatusCode != http.StatusOK {
// 		bodyBytes, _ := io.ReadAll(resp.Body)
// 		return false, fmt.Errorf("Gemini API 거부됨 (Status: %d, Body: %s)", resp.StatusCode, string(bodyBytes))
// 	}

// 	// 구글 AI 응답 구조체 맵핑
// 	var geminiResp struct {
// 		Candidates []struct {
// 			Content struct {
// 				Parts []struct {
// 					Text string `json:"text"`
// 				} `json:"parts"`
// 			} `json:"content"`
// 		} `json:"candidates"`
// 	}

// 	if err := json.NewDecoder(resp.Body).Decode(&geminiResp); err != nil {
// 		return false, fmt.Errorf("Gemini JSON 디코딩 에러: %v", err)
// 	}

// 	// 결과 파출
// 	if len(geminiResp.Candidates) > 0 && len(geminiResp.Candidates[0].Content.Parts) > 0 {
// 		rawJsonText := geminiResp.Candidates[0].Content.Parts[0].Text
		
// 		var aiResult struct {
// 			Malicious bool   `json:"malicious"`
// 			Reason    string `json:"reason"`
// 		}

// 		if err := json.Unmarshal([]byte(rawJsonText), &aiResult); err == nil {
// 			stdlog.Printf("🤖 [Gemini 2.5 Flash] 스캔 완료 - 악성여부: %t, 이유: %s", aiResult.Malicious, aiResult.Reason)
// 			return aiResult.Malicious, nil
// 		}
// 	}

// 	return false, fmt.Errorf("Gemini 응답 구조 이상")
// }