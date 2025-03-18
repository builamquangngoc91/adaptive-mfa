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