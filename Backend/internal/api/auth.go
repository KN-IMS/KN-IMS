package api

// Mirror Server 모드 콘솔 PIN 인증.
//
// 토큰: 32B 랜덤 hex(64자), 인메모리 (재시작 시 무효)
// 잠금: 10회 연속 실패 -> 5분 잠금
// PIN 해시: bcrypt, MySQL auth_state 테이블 (singleton row)
//
// 엔드포인트(인증 불필요):
//   GET  /auth/status   -> { state: "unconfigured" | "configured" | "locked" }
//   POST /auth/setup    body { pin } -> 201 { token }
//   POST /auth/login    body { pin } -> 200 { token }
//
// /api/* 진입 전 Authorize 미들웨어가 Bearer 토큰 검증.

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/KN-IG/KN-IG/Backend/internal"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

const (
	sessionTTL    = 24 * time.Hour
	lockoutLimit  = 10
	lockoutWindow = 5 * time.Minute
)

// MirrorAuth : Mirror 모드 PIN 인증 핸들러
type MirrorAuth struct {
	store internal.AuthStore

	sessMu   sync.RWMutex
	sessions map[string]time.Time // token -> expiry

	failMu      sync.Mutex
	failCount   int
	lockedUntil time.Time
}

// NewMirrorAuth : MirrorAuth 생성
func NewMirrorAuth(store internal.AuthStore) *MirrorAuth {
	return &MirrorAuth{
		store:    store,
		sessions: make(map[string]time.Time),
	}
}

type pinBody struct {
	Pin string `json:"pin"`
}

// Status : GET /auth/status
func (a *MirrorAuth) Status(c *gin.Context) {
	hash, err := a.store.GetPINHash(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	state := "configured"
	if hash == "" {
		state = "unconfigured"
	} else if a.isLocked() {
		state = "locked"
	}
	c.JSON(http.StatusOK, gin.H{"state": state})
}

// Setup : POST /auth/setup (최초 PIN 설정)
func (a *MirrorAuth) Setup(c *gin.Context) {
	var body pinBody
	if err := c.ShouldBindJSON(&body); err != nil || !validPin(body.Pin) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "pin must be 4-8 digits"})
		return
	}

	existing, err := a.store.GetPINHash(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if existing != "" {
		c.JSON(http.StatusConflict, gin.H{"error": "already configured"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Pin), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := a.store.SetPINHash(c.Request.Context(), string(hash)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"token": a.issue()})
}

// Login : POST /auth/login
func (a *MirrorAuth) Login(c *gin.Context) {
	if a.isLocked() {
		c.JSON(http.StatusLocked, gin.H{"error": "too many failed attempts, try later"})
		return
	}

	var body pinBody
	if err := c.ShouldBindJSON(&body); err != nil || !validPin(body.Pin) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid pin format"})
		return
	}

	hash, err := a.store.GetPINHash(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if hash == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "not configured"})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(body.Pin)); err != nil {
		a.recordFailure()
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid pin"})
		return
	}
	a.resetFailures()
	c.JSON(http.StatusOK, gin.H{"token": a.issue()})
}

// Authorize : /api/* 진입 미들웨어. Bearer 토큰 검증.
func (a *MirrorAuth) Authorize(c *gin.Context) {
	h := c.GetHeader("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
		return
	}
	tok := strings.TrimPrefix(h, "Bearer ")

	a.sessMu.RLock()
	exp, ok := a.sessions[tok]
	a.sessMu.RUnlock()

	if !ok || time.Now().After(exp) {
		if ok {
			a.sessMu.Lock()
			delete(a.sessions, tok)
			a.sessMu.Unlock()
		}
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
		return
	}
	c.Next()
}

func (a *MirrorAuth) issue() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand 실패는 시스템 단위 장애. 패닉이 합리적.
		panic(err)
	}
	tok := hex.EncodeToString(b[:])
	a.sessMu.Lock()
	a.sessions[tok] = time.Now().Add(sessionTTL)
	a.sessMu.Unlock()
	return tok
}

func (a *MirrorAuth) isLocked() bool {
	a.failMu.Lock()
	defer a.failMu.Unlock()
	return time.Now().Before(a.lockedUntil)
}

func (a *MirrorAuth) recordFailure() {
	a.failMu.Lock()
	defer a.failMu.Unlock()
	a.failCount++
	if a.failCount >= lockoutLimit {
		a.lockedUntil = time.Now().Add(lockoutWindow)
		a.failCount = 0
	}
}

func (a *MirrorAuth) resetFailures() {
	a.failMu.Lock()
	a.failCount = 0
	a.lockedUntil = time.Time{}
	a.failMu.Unlock()
}

func validPin(p string) bool {
	if len(p) < 4 || len(p) > 8 {
		return false
	}
	for _, c := range p {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
