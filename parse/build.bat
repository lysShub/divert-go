@REM go install golang.org/x/tools/cmd/goyacc@v0.9.1  Deprecated
@REM go install github.com/cznic/goyacc@latest
@REM go get modernc.org/golex@v1.0.5 

goyacc -l -o parser.go parser.y