FROM golang:1.24-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends gnupg age \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY go.mod ./
COPY *.go ./
# go.sum is generated here, so you do not need Go installed on your machine
RUN go mod tidy && go build -o /usr/local/bin/hsmsim .
CMD ["hsmsim"]
