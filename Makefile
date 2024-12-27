.PHONY: mockgen lint pretty
mockgen:
	bin/generate-mock.sh

lint:
	golangci-lint run ./...

pretty:
	bin/format.sh
