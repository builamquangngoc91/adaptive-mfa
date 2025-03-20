FROM golang:1.22-alpine

RUN set -eux && \
    ln -sf  /usr/share/zoneinfo/Asia/Tokyo /etc/localtime

WORKDIR /go/src

COPY ./src/go.mod ./

RUN apk upgrade --update && \
    apk add build-base && \
    apk --no-cache add git

ENV GOBIN=/usr/local/bin/
RUN go install github.com/cosmtrek/air@v1.49.0 && \
    go install golang.org/x/tools/cmd/goimports@v0.15.0 && \
    go install github.com/google/wire/cmd/wire@v0.5.0 && \
    go install go.uber.org/mock/mockgen@v0.3.0 && \
    go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@v4.16.2 && \
    go install github.com/rillig/gobco@latest

RUN wget -O- -nv https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $GOBIN v1.55.2 && \
    golangci-lint --version

CMD ["air", "-c", ".air.toml"]
