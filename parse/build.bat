@REM go install golang.org/x/tools/cmd/goyacc@v0.9.1  Deprecated
@REM go install modernc.org/goyacc@v1.0.3
@REM go install modernc.org/golex@v1.0.5 

goyacc -l -o parser.go parser.y