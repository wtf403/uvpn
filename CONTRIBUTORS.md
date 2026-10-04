# Contributors

uvpn is one person's reverse-engineering project so far. If you fix something,
put your name here.

## Author

- **node85** (kwimpnet@proton.me): project author and maintainer.

## Contributing

1. Fork and create a feature branch.
2. Keep the project stdlib-first; new dependencies need a good reason.
3. `go build ./... && go vet ./... && gofmt -l . && go test ./...` must pass
   (`gofmt -l .` must print nothing).
4. Open a pull request describing the change and why.

Commit messages: imperative mood, one-line summary, e.g.
`fix relay port byte order on SO_ORIGINAL_DST`.
