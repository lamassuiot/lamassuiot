go build -buildmode=plugin -o ./ce-aws-sm.so ./cmd/sm/main.go
go build -buildmode=plugin -o ./ce-aws-kms.so ./cmd/kms/main.go
