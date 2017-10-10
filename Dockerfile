# Run orthrus in a container:
#
# docker run --rm -it \
#   -v "$HOME/.orthrus:/root/.orthrus" \
#   petermbenjamin/orthrus "$@"

FROM golang:latest
WORKDIR /go/src/github.com/petermbenjamin/orthrus
COPY . /go/src/github.com/petermbenjamin/orthrus
RUN go get -u github.com/golang/dep/cmd/dep && dep ensure -v
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o orthrus cmd/orthrus/main.go

FROM alpine:latest
LABEL maintainer "Peter Benjamin <petermbenjamin@gmail.com>"
WORKDIR /root/
RUN apk --no-cache add ca-certificates
COPY --from=0 /go/src/github.com/petermbenjamin/orthrus/orthrus .
ENTRYPOINT ["./orthrus"]
