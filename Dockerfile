FROM golang:1.25 AS build
WORKDIR /workspace

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /workspace/bin/fake-cloud-kms ./cmd/fake-cloud-kms

FROM gcr.io/distroless/base-debian12
COPY --from=build /workspace/bin/fake-cloud-kms /usr/local/bin/fake-cloud-kms
EXPOSE 9010
ENTRYPOINT ["/usr/local/bin/fake-cloud-kms", "--grpc-listen-addr", "0.0.0.0:9010"]
