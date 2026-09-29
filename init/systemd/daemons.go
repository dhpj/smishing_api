package systemd

import(
	"os"
	"fmt"
	"syscall"
	"os/signal"

	"mycs/api/dhn"
	"mycs/configs"
	"mycs/configs/databasepool"

	"github.com/kardianos/service"
)

type Program struct{}

// 서비스 시작 시 실행되는 함수
func (p *Program) Start(s service.Service) error {
	configs.Stdlog.Println("start Service")
	serviceString := fmt.Sprintf("%v", s)

	go p.run(serviceString) // 백그라운드 실행
	return nil
}

// 실제 서비스 로직 (resultProc 실행)
func (p *Program) run(m string) {
	dhn.DhnProc()
	configs.Stdlog.Println("start DhnProc()")

	// 종료 신호 대기
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGKILL, syscall.SIGQUIT)
	<-interrupt

	configs.Stdlog.Println("stop Service")
	configs.Stdlog.Println("Stopping DB Connection: ", databasepool.DB.Stats())
	databasepool.DB.Close()
	os.Exit(0)
}

// 서비스 중지 시 실행되는 함수
func (p *Program) Stop(s service.Service) error {
	configs.Stdlog.Println("stop Service")
	return nil
}

func Manage(s service.Service) (string, error) {
	var err error
	var msg string = ""
	if len(os.Args) > 1 {
		cmd := os.Args[1]
		switch cmd {
		case "install":
			err = s.Install()
			msg = "서비스 설치"
		case "remove":
			err = s.Uninstall()
			msg = "서비스 삭제"
		case "start":
			err = s.Start()
			msg = "서비스 시작"
		case "stop":
			err = s.Stop()
			msg = "서비스 정지"
		case "restart":
			err = s.Restart()
			msg = "서비스 재시작"
		case "status":
			st, err := s.Status()
			msg = "서비스 상태 : "
			if err == nil {
				msg += string(st)
			}
		default:
			msg = "사용법: [install|remove|start|stop|restart|status]"
			return msg, nil
		}
		if err != nil {
			configs.Stdlog.Println("Error: ", err)
			os.Exit(1)
		}
		if err != nil {
			msg += " 실패"
		} else {
			msg += " 성공"
		}
		return msg, err
	}

	// 서비스 실행
	err = s.Run()
	if err != nil {
		configs.Stdlog.Println("Error: ", err)
		os.Exit(1)
	}

	return "start process!!", nil
}