package scan

import "time"

// State 是 chain_scan_state.state 的取值。
type State string

const (
	StateIdle         State = "idle"
	StateScanning     State = "scanning"
	StateCatchingUp   State = "catching_up"
	StateStalled      State = "stalled"
	StatePaused       State = "paused"
	StateUnconfigured State = "unconfigured"
)

// Health 是端点健康度。
type Health string

const (
	HealthHealthy  Health = "healthy"
	HealthCooling  Health = "cooling"
	HealthMismatch Health = "mismatch"
	HealthUnknown  Health = "unknown"
)

// EndpointHealth 一个端点的健康度，落在 chain_scan_state.endpoint_health 里。
type EndpointHealth struct {
	Label               string     `json:"label"`
	URLHash             string     `json:"urlHash"`
	Health              Health     `json:"health"`
	ConsecutiveFailures int        `json:"consecutiveFailures"`
	CoolingUntil        *time.Time `json:"coolingUntil,omitempty"`
	LastOkAt            *time.Time `json:"lastOkAt,omitempty"`
	LastError           string     `json:"lastError,omitempty"`
	LatencyMs           int        `json:"latencyMs,omitempty"`
	HeadBlock           uint64     `json:"headBlock,omitempty"`
	SpanRejected        int        `json:"spanRejected"`
}

// JobKind / JobState 见设计 §4.7、§4.9。
type JobKind string
type JobState string

const (
	JobRescan    JobKind = "rescan"
	JobAttribute JobKind = "attribute"

	JobPending JobState = "pending"
	JobRunning JobState = "running"
	JobFailed  JobState = "failed"
)

// Job 一条后台任务，落在 chain_scan_state.jobs 里；done / cancelled 后移出并写审计。
type Job struct {
	ID            string    `json:"id"`
	Kind          JobKind   `json:"kind"`
	FromBlock     uint64    `json:"fromBlock"`
	ToBlock       uint64    `json:"toBlock"`
	ProgressBlock uint64    `json:"progressBlock"`
	State         JobState  `json:"state"`
	CreatedBy     string    `json:"createdBy"`
	Reason        string    `json:"reason,omitempty"`
	LastError     string    `json:"lastError,omitempty"`
	CreatedAt     time.Time `json:"createdAt"`
}

// AlertKind 告警类型。
type AlertKind string

const (
	AlertStalled          AlertKind = "stalled"
	AlertLagging          AlertKind = "lagging"
	AlertReorg            AlertKind = "reorg"
	AlertEndpointMismatch AlertKind = "endpoint_mismatch"
	AlertJobFailed        AlertKind = "job_failed"
)

// Alert 一条未恢复的告警，落在 chain_scan_state.open_alerts 里。
type Alert struct {
	Kind          AlertKind  `json:"kind"`
	Message       string     `json:"message"`
	RaisedAt      time.Time  `json:"raisedAt"`
	WebhookSentAt *time.Time `json:"webhookSentAt,omitempty"`
}

// ChainState 对应 chain_scan_state 一行。
type ChainState struct {
	Chain          string
	ScannedToBlock uint64
	ScannedToHash  string
	HeadBlock      uint64
	State          State
	LeaseOwner     string
	LeaseUntil     *time.Time
	LastError      string
	ErrorCount     int
	ReorgCount     int
	EndpointHealth []EndpointHealth
	Jobs           []Job
	OpenAlerts     []Alert
	UpdatedAt      time.Time
}

// Alert 查找某类未恢复告警。
func (s *ChainState) Alert(kind AlertKind) *Alert {
	for index := range s.OpenAlerts {
		if s.OpenAlerts[index].Kind == kind {
			return &s.OpenAlerts[index]
		}
	}
	return nil
}
