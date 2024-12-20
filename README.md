## Windivert Demo
#### Build Demo
此方式需要在 working dir 存在 WinDivert.dll 动态库
```
go build -o reqfilter.exe reqfilter\main.go
go build -o respfilter.exe respfilter\main.go
go build -o passthru.exe passthru\main.go
```
或者用 cgo，此方式不依赖 WinDivert.dll
```
go build -tags=divert_cgo -o reqfilter.exe reqfilter\main.go
go build -tags=divert_cgo -o respfilter.exe respfilter\main.go
go build -tags=divert_cgo -o passthru.exe passthru\main.go
```
#### Run Demo
```
./reqfilter.exe

# 发 HTTP 请求
curl http://example.com
```