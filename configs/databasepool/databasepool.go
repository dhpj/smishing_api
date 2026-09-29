package databasepool

import (
	"log"
	"time"
	"database/sql"

	config "mycs/configs"
	_ "github.com/go-sql-driver/mysql"
)

var DB *sql.DB
var DB2 *sql.DB

func InitDatabase(flag bool) {
	db, err := sql.Open(config.Conf.DB, config.Conf.DBURL)
	if err != nil {
		log.Fatal(err)
	}

	db.SetMaxIdleConns(5)
	db.SetMaxOpenConns(10)
	db.SetConnMaxIdleTime(1 * time.Minute)

	DB = db

	db, err = sql.Open(config.Conf.DB2, config.Conf.DBURL2)
	if err != nil {
		log.Fatal(err)
	}

	db.SetMaxIdleConns(5)
	db.SetMaxOpenConns(10)
	db.SetConnMaxIdleTime(1 * time.Minute)

	DB2 = db
}