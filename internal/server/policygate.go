// policygate.go 上游策略级防护状态机。
//
// 11-128 通道拒绝与 11140 账号限制都不是普通账号错误：
//   - 通道拒绝换账号无效；
//   - 账号限制继续轮换会把同一请求扩散到更多账号。
//
// Handler 已在单次请求内 fail-fast。本状态机负责跨请求止损：同域短窗命中达到
// 阈值后暂停该域一段时间，期间请求在选号之前直接返回，避免持续消耗账号池。
package server

import (
	"log"
	"sync"
	"time"
)

var (
	policyChannelWindow   = 60 * time.Second
	policyChannelOpenFor  = 60 * time.Second
	policyRestrictWindow  = 5 * time.Minute
	policyRestrictOpenFor = 10 * time.Minute
)

const (
	policyChannelThreshold  = 3
	policyRestrictThreshold = 2
)

type policyGuardStatus struct {
	Blocked bool
	Until   time.Time
	Reason  string
}

// policyGuard 按 realm 维护策略级滑动窗与熔断时间。零值可用。
type policyGuard struct {
	mu           sync.Mutex
	channelHits  map[string][]time.Time
	restrictHits map[string]map[string]time.Time
	until        map[string]time.Time
	reasons      map[string]string
}

func policyRealm(realm string) string {
	if realm == "" {
		return "cn"
	}
	return realm
}

func (g *policyGuard) blockedAt(realm string, now time.Time) policyGuardStatus {
	realm = policyRealm(realm)
	g.mu.Lock()
	defer g.mu.Unlock()
	until := g.until[realm]
	if !now.Before(until) {
		if !until.IsZero() {
			delete(g.until, realm)
			delete(g.reasons, realm)
		}
		return policyGuardStatus{}
	}
	return policyGuardStatus{Blocked: true, Until: until, Reason: g.reasons[realm]}
}

func (g *policyGuard) noteChannelRefusedAt(realm string, now time.Time) bool {
	realm = policyRealm(realm)
	g.mu.Lock()
	defer g.mu.Unlock()
	if now.Before(g.until[realm]) {
		return true
	}
	if g.channelHits == nil {
		g.channelHits = make(map[string][]time.Time)
	}
	hits := append(g.channelHits[realm], now)
	cut := 0
	for cut < len(hits) && now.Sub(hits[cut]) > policyChannelWindow {
		cut++
	}
	hits = hits[cut:]
	g.channelHits[realm] = hits
	if len(hits) < policyChannelThreshold {
		return false
	}
	g.openLocked(realm, now, policyChannelOpenFor, "channel_refused")
	g.channelHits[realm] = nil
	return true
}

func (g *policyGuard) noteAccountRestrictedAt(realm, uid string, now time.Time) bool {
	realm = policyRealm(realm)
	g.mu.Lock()
	defer g.mu.Unlock()
	if now.Before(g.until[realm]) {
		return true
	}
	if g.restrictHits == nil {
		g.restrictHits = make(map[string]map[string]time.Time)
	}
	hits := g.restrictHits[realm]
	if hits == nil {
		hits = make(map[string]time.Time)
		g.restrictHits[realm] = hits
	}
	hits[uid] = now
	for id, at := range hits {
		if now.Sub(at) > policyRestrictWindow {
			delete(hits, id)
		}
	}
	if len(hits) < policyRestrictThreshold {
		return false
	}
	g.openLocked(realm, now, policyRestrictOpenFor, "account_restricted")
	g.restrictHits[realm] = nil
	return true
}

func (g *policyGuard) openLocked(realm string, now time.Time, duration time.Duration, reason string) {
	if g.until == nil {
		g.until = make(map[string]time.Time)
	}
	if g.reasons == nil {
		g.reasons = make(map[string]string)
	}
	g.until[realm] = now.Add(duration)
	g.reasons[realm] = reason
	log.Printf("WARN: [server] upstream policy guard open realm=%s reason=%s until=%s",
		realm, reason, g.until[realm].Format(time.RFC3339))
}
