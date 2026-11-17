# docker build -t attckus .
# docker run --rm -v "$PWD:/src" attckus scan /src
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/attckus ./cmd/attckus

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/attckus /attckus
USER nonroot:nonroot
ENTRYPOINT ["/attckus"]
