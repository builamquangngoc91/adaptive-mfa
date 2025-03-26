include src/.env

DOCKER_RUN=docker compose -f docker/local.docker-compose.yaml run --rm amfa

up:
	docker compose -f docker/local.docker-compose.yaml up -d
down:
	docker compose -f docker/local.docker-compose.yaml down
build:
	docker compose -f docker/local.docker-compose.yaml build

log:
	docker compose -f docker/local.docker-compose.yaml logs -f amfa

# migrations
MIGRATIONS_DIR=db/migrations
MIGRATE=migrate -path=$(MIGRATIONS_DIR) -verbose
DSN="postgres://$(AMFA_DB_USER):$(AMFA_DB_PASSWORD)@$(AMFA_DB_HOST):$(AMFA_DB_PORT)/$(AMFA_DB_NAME)?sslmode=disable"
migrate-up:
	$(DOCKER_RUN) $(MIGRATE) -database $(DSN) up 
migrate-down:
	$(DOCKER_RUN) $(MIGRATE) -database $(DSN) down

mockgen:
	$(DOCKER_RUN) go generate ./...