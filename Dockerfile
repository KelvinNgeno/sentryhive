FROM golang:1.23-bookworm AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -o /sentryhive ./cmd/sentryhive

FROM debian:bookworm-slim
RUN useradd -r -s /bin/false sentryhive
WORKDIR /app
COPY --from=build /sentryhive /app/sentryhive
COPY config.yaml /app/config.yaml
RUN mkdir -p /app/data && chown -R sentryhive:sentryhive /app
USER sentryhive

EXPOSE 2222 8080 2323 2121
ENTRYPOINT ["/app/sentryhive", "-config", "/app/config.yaml"]
