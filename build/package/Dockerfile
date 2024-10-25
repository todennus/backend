FROM golang:1.23-alpine AS build

WORKDIR /oauth2-service

RUN apk add -U --no-cache ca-certificates

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . ./

RUN CGO_ENABLED=0 go build -ldflags="-w -s" -o /service ./cmd/main.go

FROM scratch

WORKDIR /

COPY --from=build /service /
COPY --from=build /oauth2-service/template /template

EXPOSE 8080

ENTRYPOINT [ "/service", "--env", ""]
