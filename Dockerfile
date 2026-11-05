# docker build -t groot .
# docker run --rm -v "$PWD:/src" groot scan /src
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/groot ./cmd/groot

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/groot /groot
USER nonroot:nonroot
ENTRYPOINT ["/groot"]
