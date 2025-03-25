package middleware

import (
	"net/http"
	"strconv"
	"time"

	"adaptive-mfa/pkg/monitor"
	"adaptive-mfa/server"
)

type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *statusRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func PrometheusMiddleware(next server.Handler) server.Handler {
	return func(w http.ResponseWriter, r *http.Request) {
		monitor.ActiveRequestsGauge.Inc()
		start := time.Now()

		recorder := &statusRecorder{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		next(recorder, r)

		method := r.Method
		path := r.URL.Path
		status := strconv.Itoa(recorder.statusCode)

		duration := time.Since(start).Seconds()
		monitor.HttpRequestCounter.WithLabelValues(status, path, method).Inc()
		monitor.LatencyHistogram.WithLabelValues(status, path, method).Observe(duration)
		monitor.LatencySummary.WithLabelValues(status, path, method).Observe(duration)
		monitor.ActiveRequestsGauge.Dec()
	}
}
