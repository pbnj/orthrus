FROM golang:latest
WORKDIR /go/src/github.com/petermbenjamin/orthrus
COPY . /go/src/github.com/petermbenjamin/orthrus
RUN go get -u github.com/golang/dep/cmd/dep && dep ensure -v
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o orthrus cmd/orthrus/main.go

FROM alpine:latest
WORKDIR /root/
COPY --from=0 /go/src/github.com/petermbenjamin/orthrus/orthrus .
ENTRYPOINT ["./orthrus"]
