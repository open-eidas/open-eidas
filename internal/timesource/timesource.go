// Package timesource surveille l'horloge du service face à des sources de
// temps de référence (serveurs NTP de laboratoires de métrologie) et décide
// si l'autorité est en droit de signer.
//
// ETSI EN 319 421 exige que l'heure d'un jeton soit traçable jusqu'à UTC et
// que la TSA cesse d'émettre dès qu'elle ne peut plus garantir la précision
// qu'elle annonce. C'est ce que met en œuvre ce paquet : tant que la dérive
// mesurée reste sous le seuil, le service signe ; au-delà, il refuse avec
// timeNotAvailable plutôt que de produire un jeton non fiable.
package timesource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/beevik/ntp"

	"github.com/open-eidas/open-eidas/internal/audit"
)

// Policy décrit la conduite à tenir lorsque l'heure n'est plus vérifiable.
type Policy string

const (
	// PolicyEnforce refuse de signer tant que la traçabilité n'est pas établie.
	PolicyEnforce Policy = "enforce"
	// PolicyMonitor journalise l'écart mais laisse le service signer. Réservé
	// aux environnements de développement sans accès aux serveurs de temps.
	PolicyMonitor Policy = "monitor"
	// PolicyDisabled désactive toute surveillance.
	PolicyDisabled Policy = "disabled"
)

func ParsePolicy(s string) (Policy, error) {
	switch Policy(strings.ToLower(strings.TrimSpace(s))) {
	case PolicyEnforce:
		return PolicyEnforce, nil
	case PolicyMonitor:
		return PolicyMonitor, nil
	case PolicyDisabled:
		return PolicyDisabled, nil
	default:
		return "", fmt.Errorf("politique de temps inconnue: %q (enforce, monitor ou disabled)", s)
	}
}

// ErrTimeNotTraceable signale que l'heure locale n'est plus rattachable à UTC
// dans les limites annoncées.
var ErrTimeNotTraceable = errors.New("heure non traçable jusqu'à UTC")

type Options struct {
	Servers      []string
	Policy       Policy
	MaxOffset    time.Duration
	MaxAge       time.Duration
	MinSources   int
	PollInterval time.Duration
	Timeout      time.Duration
	Logger       *slog.Logger
	Recorder     Recorder
}

// Recorder consigne les mesures de temps dans le journal d'audit.
type Recorder interface {
	Append(event string, data map[string]any) error
}

// Sample est une mesure ponctuelle face à une source de temps.
type Sample struct {
	Server  string
	Offset  time.Duration
	RTT     time.Duration
	Stratum uint8
	At      time.Time
	Err     string
}

func (s Sample) ok() bool { return s.Err == "" }

// MarshalJSON publie les durées sous forme lisible plutôt qu'en nanosecondes.
func (s Sample) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Server  string    `json:"server"`
		Offset  string    `json:"offset"`
		RTT     string    `json:"rtt"`
		Stratum uint8     `json:"stratum"`
		At      time.Time `json:"at"`
		Err     string    `json:"error,omitempty"`
	}{s.Server, s.Offset.String(), s.RTT.String(), s.Stratum, s.At, s.Err})
}

// Status est l'état de traçabilité publié par le service.
type Status struct {
	Policy    Policy        `json:"policy"`
	Traceable bool          `json:"traceable"`
	Reason    string        `json:"reason,omitempty"`
	Offset    time.Duration `json:"-"`
	Spread    time.Duration `json:"-"`
	OffsetStr string        `json:"offset"`
	SpreadStr string        `json:"spread"`
	LastSync  *time.Time    `json:"last_sync,omitempty"`
	Sources   []Sample      `json:"sources"`
}

type Monitor struct {
	opts Options

	mu     sync.RWMutex
	status Status
}

func New(o Options) (*Monitor, error) {
	if o.Policy == "" {
		o.Policy = PolicyEnforce
	}
	if o.Policy != PolicyDisabled && len(o.Servers) == 0 {
		return nil, errors.New("timesource: aucune source de temps configurée")
	}
	if o.MinSources <= 0 {
		o.MinSources = 1
	}
	if o.MinSources > len(o.Servers) && o.Policy != PolicyDisabled {
		return nil, fmt.Errorf("timesource: %d sources exigées mais %d configurées", o.MinSources, len(o.Servers))
	}
	if o.MaxOffset <= 0 {
		o.MaxOffset = 500 * time.Millisecond
	}
	if o.MaxAge <= 0 {
		o.MaxAge = time.Hour
	}
	if o.PollInterval <= 0 {
		o.PollInterval = 5 * time.Minute
	}
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	m := &Monitor{opts: o}
	if o.Policy == PolicyDisabled {
		m.status = Status{Policy: PolicyDisabled, Traceable: true, Reason: "surveillance désactivée"}
	} else {
		m.status = Status{Policy: o.Policy, Reason: "aucune mesure effectuée"}
	}
	return m, nil
}

// Start effectue une première mesure puis lance la surveillance périodique.
// La goroutine s'arrête avec le contexte.
func (m *Monitor) Start(ctx context.Context) {
	if m.opts.Policy == PolicyDisabled {
		m.logger().Warn("surveillance de l'heure désactivée : les jetons ne sont pas traçables jusqu'à UTC")
		return
	}
	m.poll(ctx)
	go func() {
		ticker := time.NewTicker(m.opts.PollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.poll(ctx)
			}
		}
	}()
}

// Now retourne l'heure à estampiller, ou une erreur si la traçabilité n'est
// pas établie et que la politique impose le refus.
func (m *Monitor) Now() (time.Time, error) {
	status := m.Status()
	if !status.Traceable && m.opts.Policy == PolicyEnforce {
		return time.Time{}, fmt.Errorf("%w: %s", ErrTimeNotTraceable, status.Reason)
	}
	return time.Now(), nil
}

func (m *Monitor) Status() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

func (m *Monitor) poll(ctx context.Context) {
	samples := make([]Sample, 0, len(m.opts.Servers))
	for _, server := range m.opts.Servers {
		if ctx.Err() != nil {
			return
		}
		samples = append(samples, m.query(server))
	}
	status := evaluate(samples, m.opts, time.Now())

	m.mu.Lock()
	previous := m.status
	m.status = status
	m.mu.Unlock()

	m.record(status)

	switch {
	case !status.Traceable && m.opts.Policy == PolicyEnforce:
		m.logger().Error("heure non traçable : émission de jetons suspendue",
			"raison", status.Reason, "ecart", status.OffsetStr, "dispersion", status.SpreadStr)
	case !status.Traceable:
		m.logger().Warn("heure non traçable (politique monitor : émission maintenue)",
			"raison", status.Reason, "ecart", status.OffsetStr)
	case !previous.Traceable:
		m.logger().Info("traçabilité de l'heure rétablie",
			"ecart", status.OffsetStr, "dispersion", status.SpreadStr)
	default:
		m.logger().Info("heure vérifiée", "ecart", status.OffsetStr, "dispersion", status.SpreadStr)
	}
}

// record consigne la mesure : c'est cette trace qu'un auditeur relit pour
// vérifier que l'heure était sous contrôle au moment d'une émission.
func (m *Monitor) record(status Status) {
	if m.opts.Recorder == nil {
		return
	}
	sources := make(map[string]any, len(status.Sources))
	for _, s := range status.Sources {
		if s.ok() {
			sources[s.Server] = s.Offset.String()
		} else {
			sources[s.Server] = "erreur: " + s.Err
		}
	}
	if err := m.opts.Recorder.Append(audit.EventTimeMeasurement, map[string]any{
		"traceable":  status.Traceable,
		"offset":     status.OffsetStr,
		"spread":     status.SpreadStr,
		"reason":     status.Reason,
		"sources":    sources,
		"max_offset": m.opts.MaxOffset.String(),
	}); err != nil {
		m.logger().Error("mesure de temps non consignée au journal d'audit", "err", err)
	}
}

func (m *Monitor) query(server string) Sample {
	now := time.Now()
	resp, err := ntp.QueryWithOptions(server, ntp.QueryOptions{Timeout: m.opts.Timeout})
	if err != nil {
		return Sample{Server: server, At: now, Err: err.Error()}
	}
	if err := resp.Validate(); err != nil {
		return Sample{Server: server, At: now, Stratum: resp.Stratum, Err: err.Error()}
	}
	return Sample{
		Server:  server,
		Offset:  resp.ClockOffset,
		RTT:     resp.RTT,
		Stratum: resp.Stratum,
		At:      now,
	}
}

// evaluate est la règle de décision, isolée du réseau pour rester testable.
// L'heure est jugée traçable lorsque le quorum de sources est atteint, que
// l'écart mesuré et la dispersion entre sources restent sous le seuil, et que
// la mesure n'est pas périmée.
func evaluate(samples []Sample, opts Options, now time.Time) Status {
	status := Status{Policy: opts.Policy, Sources: samples}

	var offsets []time.Duration
	var newest time.Time
	for _, s := range samples {
		if !s.ok() {
			continue
		}
		offsets = append(offsets, s.Offset)
		if s.At.After(newest) {
			newest = s.At
		}
	}

	if len(offsets) > 0 {
		status.LastSync = &newest
		status.Offset = maxAbs(offsets)
		status.Spread = spread(offsets)
	}
	status.OffsetStr = status.Offset.String()
	status.SpreadStr = status.Spread.String()

	switch {
	case len(offsets) < opts.MinSources:
		status.Reason = fmt.Sprintf("%d source(s) de temps jointe(s) sur les %d exigées",
			len(offsets), opts.MinSources)
	case now.Sub(newest) > opts.MaxAge:
		status.Reason = fmt.Sprintf("dernière mesure datant de %s (limite %s)",
			now.Sub(newest).Round(time.Second), opts.MaxAge)
	case status.Offset > opts.MaxOffset:
		status.Reason = fmt.Sprintf("dérive de %s supérieure au seuil de %s",
			status.Offset, opts.MaxOffset)
	case status.Spread > opts.MaxOffset:
		status.Reason = fmt.Sprintf("désaccord de %s entre les sources de temps (seuil %s)",
			status.Spread, opts.MaxOffset)
	default:
		status.Traceable = true
	}
	return status
}

func maxAbs(durations []time.Duration) time.Duration {
	var max time.Duration
	for _, d := range durations {
		if d < 0 {
			d = -d
		}
		if d > max {
			max = d
		}
	}
	return max
}

func spread(durations []time.Duration) time.Duration {
	if len(durations) < 2 {
		return 0
	}
	min, max := durations[0], durations[0]
	for _, d := range durations[1:] {
		if d < min {
			min = d
		}
		if d > max {
			max = d
		}
	}
	return max - min
}

func (m *Monitor) logger() *slog.Logger {
	if m.opts.Logger != nil {
		return m.opts.Logger
	}
	return slog.Default()
}
