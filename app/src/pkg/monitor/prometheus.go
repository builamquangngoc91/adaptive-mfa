package monitor

import "github.com/prometheus/client_golang/prometheus"

var (
	HttpRequestCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Total number of HTTP requests received",
	}, []string{"status", "path", "method"})

	ActiveRequestsGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "http_active_requests",
			Help: "Number of active connections to the service",
		},
	)

	LatencyHistogram = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "http_request_duration_seconds",
		Help:    "Duration of HTTP requests",
		Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10},
	}, []string{"status", "path", "method"})

	LatencySummary = prometheus.NewSummaryVec(prometheus.SummaryOpts{
		Name: "http_request_duration_seconds_summary",
		Help: "Duration of HTTP requests summary",
		Objectives: map[float64]float64{
			0.5:  0.05,
			0.9:  0.01,
			0.99: 0.001,
		},
	}, []string{"status", "path", "method"})

	SMSSendCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sms_send_total",
		Help: "Total number of SMS send",
	}, []string{"phone"})

	EmailSendCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "email_send_total",
		Help: "Total number of email send",
	}, []string{"email"})
)
