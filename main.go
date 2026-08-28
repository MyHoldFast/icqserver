package main

import (
	"log"
	"os"
	"strconv"
)

func main() {
	srv, err := NewServer(ServerHost, ServerPort, DBPath, true)
	if err != nil {
		log.Fatal(err)
	}
	srv.BosHost = os.Getenv("ICQ_BOS_HOST")
	if v := os.Getenv("ICQ_BOS_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			srv.BosPort = p
		}
	}
	if err := srv.Start(); err != nil {
		log.Fatal(err)
	}
}
