package main

import (
	"os"
	"fmt"
	"reflect"
	
	"mycs/init/systemd"
	config "mycs/configs"
	"mycs/configs/databasepool"

	"github.com/kardianos/service"
)

const (
	name        = "DHNApi"
	description = "대형네트웍스 통합 API 센터"
)

func main() {

	config.InitConfig()

	val := reflect.ValueOf(config.Conf)
	typ := reflect.TypeOf(config.Conf)
	config.Stdlog.Println("------------------------------------------------------------------------------")

	for i := 0; i < val.NumField(); i++ {
		field := typ.Field(i)
		value := val.Field(i)
		config.Stdlog.Println(fmt.Sprintf("%s: %v", field.Name, value.Interface()))
	}

	config.Stdlog.Println("------------------------------------------------------------------------------")

	databasepool.InitDatabase(true)

	svcConfig := &service.Config{
		Name:        name,
		DisplayName: name,
		Description: description,
	}

	prg := &systemd.Program{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		config.Errlog.Println("Error: ", err)
		os.Exit(1)
	}

	status, err := systemd.Manage(s)
	if err != nil {
		config.Errlog.Println(status, " Error: ", err)
		os.Exit(1)
	}
	fmt.Println(status)
}