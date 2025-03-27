# adaptive-mfa

## 🚀 Set up Development Environment (First-Time Setup)

### 1. Install Docker

- [https://www.docker.com/](https://www.docker.com/)

### 2. Clone the Repository

```sh
git clone https://github.com/builamquangngoc91/adaptive-mfa.git
cd adaptive-mfa
cd app
```

3. Start Server

# Start all services (App, Postgres, Redis, Prometheus)
```
make up
```

# View logs
```
make log
```

# ⚠️ NOTE:
# DB initialization may take time on the first run.
# If startup fails, try:
```
make down
make up
```

4. Database Migration

# Run PostgreSQL migrations
```
make migrate-up

make migrate-up-test
```

5. Seed Data (Optional)

# Insert demo/test seed data
```
make seed
```

⸻

🔌 API Connectivity Check

You can test the system using Postman, Insomnia, or curl.

Example Login Request

Endpoint
```

POST http://localhost:8081/auth/login

Request Body

{
  "username": "admin@example.com",
  "password": "securepassword"
}
```

Example Response
```

{
  "reference_id": "abc123",
  "mfa_required": true
}
```

Use reference_id in subsequent MFA verification requests.

⸻

📈 Benchmarking & Monitoring

Prometheus is integrated to provide performance and usage metrics.

1. Prometheus UI

Access via browser:

```http://localhost:9090```

2. Useful Prometheus Metrics
	•	http_requests_total – total API calls
	•	mfa_challenges_total – number of MFA challenges
	•	risk_evaluation_duration_seconds – latency of risk assessments

3. Load Testing (Optional)

You can simulate traffic using tools like:

hey

```
hey -n 1000 -c 20 -m POST http://localhost:8081/auth/login
```

wrk

```
wrk -t4 -c100 -d30s http://localhost:8081/auth/login
```

⸻

🛠 Developer Commands

# Run all tests
```
make test
```

# Run benchmark tests
```
make bench
```

# Format code lint (WIP)

```
make lint
```

# Generate mocks (if used)
```
make mockgen
```

⸻

📚 References
	•	README.md: Project overview and architecture
	•	docs/: (Optional) Contains system diagrams, risk logic, and C4 breakdown

⸻
