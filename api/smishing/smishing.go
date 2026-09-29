package smishing

import (
	"database/sql"
	"encoding/json"

	"mycs/configs"
	cm "mycs/internal/commons"
	"mycs/configs/databasepool"

	"github.com/valyala/fasthttp"
)

func CheckUri(c *fasthttp.RequestCtx){
	
	// 1. 클라이언트가 보낸 원본 데이터 슥싹하기
	userid := c.Request.Header.Peek("userid") // 헤더에서 userid 추출
	reqBody := c.PostBody()                   // 바디에서 json 원본 그대로 추출

	// 2. 로컬 API로 보낼 Request/Response 객체 빌리기 (fasthttp 메모리 최적화 기법)
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req) // 다 쓰면 메모리 풀에 반납!

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	// 3. 로컬 API 목적지 세팅
	targetUrl := "http://localhost:" + configs.Conf.PORT + "/check_uri"
	req.SetRequestURI(targetUrl)
	req.Header.SetMethod(fasthttp.MethodPost)
	req.Header.SetContentType("application/json")

	// 4. 추출했던 userid 헤더에 꽂아주기
	if len(userid) > 0 {
		req.Header.Set("userid", "smishing")
	}

	// 5. 추출했던 바디 데이터 그대로 꽂아주기
	req.SetBody(reqBody)

	// 6. 🚀 로컬 API로 진짜 발송! (fasthttp.Do 사용)
	err := fasthttp.Do(req, resp)
	if err != nil {
		// 로컬 서버가 죽어있거나 통신 에러가 났을 때의 방어 로직
		configs.Errlog.Println("로컬 API 발송 에러 :", err)
		c.SetStatusCode(fasthttp.StatusInternalServerError)
		c.SetContentType("application/json")
		c.SetBodyString(`{"code": "500", "message": "내부 API 통신 중 에러가 발생했습니다."}`)
		return
	}

	// 7. 로컬 API가 뱉어낸 리스폰스 결과를 그대로 클라이언트에게 복붙해서 리턴!
	c.SetStatusCode(fasthttp.StatusOK)             // 상태 코드 (예: 200, 400 등)
	c.SetContentTypeBytes(resp.Header.ContentType()) // 응답 컨텐츠 타입
	c.SetBody(resp.Body())                         // 응답 바디 데이터 (code, message 등)
}

func SetUserid(c *fasthttp.RequestCtx) {
	androidID := string(c.Request.Header.Peek("android_id"))

	
	if androidID == "" {
		c.SetStatusCode(fasthttp.StatusBadRequest)
		c.SetContentType("application/json")
		c.SetBodyString(`{"error": "android_id 헤더가 누락되었습니다."}`)
		return
	}

	var (
		newUserID string
		cnt sql.NullInt16
		uId sql.NullString
	)
	databasepool.DB2.QueryRow("select count(1), userid from DHN_CLIENT_LIST where android_id = ?", androidID).Scan(&cnt, &uId)

	if cnt.Valid {
		if cnt.Int16 > 0 {
			newUserID = uId.String
		} else {
			newUserID = cm.GenerateRandomString(15)
			databasepool.DB2.Exec("insert into DHN_CLIENT_LIST (userid, android_id, sign_in_ip) values (?, ?, ?)", newUserID, androidID, c.RemoteIP().String())
		}
	} else {
		c.SetStatusCode(fasthttp.StatusInternalServerError)
		c.SetContentType("application/json")
		c.SetBodyString(`{"code": "500", "message": "내부 API 통신 중 에러가 발생했습니다."}`)
		return
	}
	
	configs.Stdlog.Println("신규 발급 - AndroidID:", androidID, " / UserID:", newUserID)

	// ③ JSON 응답 포맷 만들기
	res := map[string]string{
		"userid": newUserID,
	}

	resBytes, err := json.Marshal(res)
	if err != nil {
		configs.Errlog.Println("JSON 마샬링 에러:", err)
		c.SetStatusCode(fasthttp.StatusInternalServerError)
		return
	}

	// ④ 클라이언트에게 리턴!
	c.SetStatusCode(fasthttp.StatusOK)
	c.SetContentType("application/json")
	c.SetBody(resBytes)
}

// 💡 클라이언트가 POST Body로 보낼 요청 구조체
type adRequestParams struct {
	Type int `json:"type"` // 1: 상단 헤더 노출, 2: ... 등등 노출 구분 플래그
}

// 💡 JSON 리스폰스용 구조체
type adImgResponse struct {
	Id      int64  `json:"id"` // 🚀 int64 타입으로 변경하여 매핑 유연성 확보!
	ImgUrl  string `json:"img_url"`
	ImgLink string `json:"img_link"`
}

// 💡 DB에서 데이터를 긁어올 때 임시로 담아둘 내부 구조체
type adRowData struct {
	id         int64
	postUserid string
	adType     int // 테이블의 type 컬럼
	adPtype    int // 테이블의 ptype 컬럼
	imgUrl     string
	imgLink    string
}

func GetAdImg(c *fasthttp.RequestCtx) {
	// ① 헤더 및 클라이언트 IP 추출
	userid := string(c.Request.Header.Peek("userid"))
	userip := c.RemoteIP().String()

	// ② POST Body에서 json 데이터(type) 파싱하기
	var reqBody adRequestParams
	if err := json.Unmarshal(c.PostBody(), &reqBody); err != nil {
		configs.Errlog.Println("GetAdImg 바디 JSON 파싱 에러:", err)
		c.SetStatusCode(fasthttp.StatusBadRequest)
		c.SetContentType("application/json")
		c.SetBodyString(`{"code": "400", "message": "잘못된 요청 바디 포맷입니다."}`)
		return
	}

	configs.Stdlog.Println("GetAdImg 요청 - userid:", userid, "/ ip:", userip, "/ req_type(노출구분):", reqBody.Type)

	// ③ limit 기준값 조회 (IMG_CNT 테이블)
	var cnt sql.NullInt16
	err := databasepool.DB2.QueryRow("select cnt from DHN_AD_IMG_CNT where type = ?", reqBody.Type).Scan(&cnt)
	if err != nil {
		configs.Errlog.Println("IMG_CNT 조회 에러:", err)
		c.SetStatusCode(fasthttp.StatusInternalServerError)
		c.SetContentType("application/json")
		c.SetBodyString(`[]`)
		return
	}

	// 기본 limit 값 설정
	limitInt := 1
	if cnt.Valid && cnt.Int16 > 0 {
		limitInt = int(cnt.Int16)
	}

	// ④ 조건에 맞는 광고 데이터 조회 (형님 피드백 + reqBody.Type 완벽 반영!)
	sqlStr := `
		SELECT 
			a.id, 
			IFNULL(a.post_userid, ''), 
			a.type, 
			a.ptype, 
			IFNULL(a.img_url, ''), 
			IFNULL(a.img_link, '')
		FROM 
			DHN_AD a
		INNER JOIN DHN_AD_CNT c 
			ON a.id = c.ad_id 
			AND a.ptype = c.ptype
		WHERE 
			a.useyn = 'Y'
			AND a.type = ?                  -- 🚀 요청 바디로 받은 type 매칭!
			AND (c.left = -1 OR c.left > 0)
		ORDER BY 
			a.id DESC
		LIMIT ?`

	rows, err := databasepool.DB2.Query(sqlStr, reqBody.Type, limitInt)
	if err != nil {
		configs.Errlog.Println("DHN_AD 조회 에러:", err)
		c.SetStatusCode(fasthttp.StatusInternalServerError)
		c.SetContentType("application/json")
		c.SetBodyString(`[]`)
		return
	}
	defer rows.Close() // 🚨 커넥션 누수 방지!

	adList := make([]adImgResponse, 0)
	tempRows := make([]adRowData, 0)

	// ⑤ rows 돌면서 데이터 가추출 및 리스폰스 JSON 매핑
	for rows.Next() {
		var row adRowData
		if scanErr := rows.Scan(&row.id, &row.postUserid, &row.adType, &row.adPtype, &row.imgUrl, &row.imgLink); scanErr != nil {
			configs.Errlog.Println("DHN_AD Scan 에러:", scanErr)
			continue
		}

		// 로그 적재 및 카운트 차감용 임시 슬라이스에 보관
		tempRows = append(tempRows, row)

		// 클라이언트 내려줄 알맹이 배열에 추가
		adList = append(adList, adImgResponse{
			Id:      row.id, // 🚀 컴파일 에러 해결됨 (int64 동기화)
			ImgUrl:  row.imgUrl,
			ImgLink: row.imgLink,
		})
	}

	// ⑥ 🚀 광고 노출 로그 적재 (DHN_AD_LOG) 및 잔여 횟수 차감 (DHN_AD_CNT)
	logSql := `INSERT INTO DHN_AD_LOG (ad_id, type, ptype, userid, c_ip) VALUES (?, ?, 1, ?, ?)`

	updateCntQuery := `
        UPDATE DHN_AD_CNT 
        SET ` + "`left`" + ` = CASE 
                        WHEN ` + "`left`" + ` = -1 THEN -1 
                        WHEN ` + "`left`" + ` > 0 THEN ` + "`left`" + ` - 1 
                        ELSE 0 
                     END 
        WHERE ad_id = ? AND ptype = ?` // 🚀 컬럼명 DDL 명세에 맞게 ad_id로 변경!
	
	for _, ad := range tempRows {
		// 1. 로그 인서트
		_, logErr := databasepool.DB2.Exec(logSql, ad.id, ad.adType, userid, userip)
		if logErr != nil {
			configs.Errlog.Println("DHN_AD_LOG 적재 실패 (ad_id:", ad.id, ") :", logErr)
		}

		// 2. 카운트 차감 처리 (변수명 오타 및 DB2 인스턴스 완전 교정)
		_, cntErr := databasepool.DB2.Exec(updateCntQuery, ad.id, ad.adPtype)
		if cntErr != nil {
			configs.Errlog.Println("❌ 광고 카운트 차감 실패 (AdID:", ad.id, ", PType:", ad.adPtype, "):", cntErr)
		}
	}

	// ⑦ JSON 마샬링
	resBytes, err := json.Marshal(adList)
	if err != nil {
		configs.Errlog.Println("JSON 마샬링 에러:", err)
		c.SetStatusCode(fasthttp.StatusInternalServerError)
		return
	}

	// ⑧ 최종 리스폰스 전송!
	c.SetStatusCode(fasthttp.StatusOK)
	c.SetContentType("application/json")
	c.SetBody(resBytes)
}














