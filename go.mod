module github.com/sagernet/quic-go

go 1.25.0

require (
	github.com/quic-go/qpack v0.6.0
	golang.org/x/crypto v0.54.0
	golang.org/x/net v0.56.0
	golang.org/x/sys v0.47.0
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	golang.org/x/exp v0.0.0-20240904232852-e7e105dedf7e // indirect
)

require (
	github.com/jordanlewis/gcassert v0.0.0-20250430164644-389ef753e22e // indirect
	github.com/metacubex/utls v1.8.7
	github.com/stretchr/testify v1.11.1 // indirect
	go.uber.org/mock v0.5.2 // indirect
	golang.org/x/mod v0.37.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	golang.org/x/tools v0.47.0 // indirect
)

tool (
	github.com/jordanlewis/gcassert/cmd/gcassert
	go.uber.org/mock/mockgen
)
