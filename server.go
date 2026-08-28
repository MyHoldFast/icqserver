package main

import (
	"log"
	"net"
	"sync"
)

type Server struct {
	Host                string
	Port                int
	BosHost             string
	BosPort             int
	Storage             *Storage
	RegistrationEnabled bool

	mu             sync.Mutex
	sessions       map[string]*Session
	pendingCookies map[string]string

	listener net.Listener
}

func NewServer(host string, port int, dbPath string, registrationEnabled bool) (*Server, error) {
	st, err := NewStorage(dbPath)
	if err != nil {
		return nil, err
	}
	return &Server{
		Host:                host,
		Port:                port,
		Storage:             st,
		RegistrationEnabled: registrationEnabled,
		sessions:            map[string]*Session{},
		pendingCookies:      map[string]string{},
	}, nil
}

func (s *Server) Start() error {
	addr := netJoin(s.Host, s.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.listener = ln
	log.Printf("ICQ Server started on %s (db: %s)", addr, s.Storage.dbPath)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		sess := NewSession(conn, s)
		go sess.Run()
	}
}

func (s *Server) Stop() {
	if s.listener != nil {
		s.listener.Close()
	}
	s.mu.Lock()
	sessions := make([]*Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	s.mu.Unlock()
	for _, sess := range sessions {
		sess.cleanup()
	}
	s.Storage.Close()
}

func (s *Server) getSession(uin string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[uin]
}

func (s *Server) setSession(uin string, sess *Session) {
	s.mu.Lock()
	s.sessions[uin] = sess
	s.mu.Unlock()
}

func (s *Server) deleteSessionIfSame(uin string, sess *Session) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.sessions[uin]; ok && cur == sess {
		delete(s.sessions, uin)
		return true
	}
	return false
}

func (s *Server) deleteSession(uin string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, uin)
}

func (s *Server) forEachSession(f func(uin string, sess *Session)) {
	s.mu.Lock()
	snapshot := make(map[string]*Session, len(s.sessions))
	for k, v := range s.sessions {
		snapshot[k] = v
	}
	s.mu.Unlock()
	for k, v := range snapshot {
		f(k, v)
	}
}

func (s *Server) popPendingCookie(cookie string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	uin, ok := s.pendingCookies[cookie]
	if ok {
		delete(s.pendingCookies, cookie)
	}
	return uin, ok
}

func (s *Server) setPendingCookie(cookie []byte, uin string) {
	s.mu.Lock()
	s.pendingCookies[string(cookie)] = uin
	s.mu.Unlock()
}

func netJoin(host string, port int) string {
	return host + ":" + itoa(port)
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte('0' + v%10)}, b...)
		v /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
