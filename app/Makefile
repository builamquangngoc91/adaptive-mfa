include src/.env

DOCKER_RUN=docker compose -f docker/local.docker-compose.yaml run --rm amfa
DOCKER_RUN_TEST=docker compose -f docker/local.docker-compose.yaml run --rm amfa-test

up:
	docker compose -f docker/local.docker-compose.yaml up -d
down:
	docker compose -f docker/local.docker-compose.yaml down
build:
	docker compose -f docker/local.docker-compose.yaml build

test:
	docker compose -f docker/local.docker-compose.yaml run --rm amfa-test go test -v ./...

log:
	docker compose -f docker/local.docker-compose.yaml logs -f amfa

log-test:
	docker compose -f docker/local.docker-compose.yaml logs -f amfa-test

# migrations
MIGRATIONS_DIR=db/migrations
MIGRATE=migrate -path=$(MIGRATIONS_DIR) -verbose
DSN="postgres://$(AMFA_DB_USER):$(AMFA_DB_PASSWORD)@$(AMFA_DB_HOST):$(AMFA_DB_PORT)/$(AMFA_DB_NAME)?sslmode=disable"
DSN_TEST="postgres://$(AMFA_DB_USER):$(AMFA_DB_PASSWORD)@$(AMFA_DB_HOST):$(AMFA_DB_PORT)/$(AMFA_DB_NAME)_test?sslmode=disable"
migrate-up:
	$(DOCKER_RUN) $(MIGRATE) -database $(DSN) up 

migrate-down:
	$(DOCKER_RUN) $(MIGRATE) -database $(DSN) down

migrate-up-test:
	$(DOCKER_RUN_TEST) $(MIGRATE) -database $(DSN_TEST) up 

migrate-down-test:
	$(DOCKER_RUN_TEST) $(MIGRATE) -database $(DSN_TEST) down

mockgen:
	$(DOCKER_RUN) go generate ./...

benchmark:
	$(DOCKER_RUN_TEST) go test -bench=. -benchmem -cpu=1,2,4 ./...

