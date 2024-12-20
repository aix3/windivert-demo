## Windivert Demo
#### Build Demo
此方式需要在 working dir 存在 WinDivert.dll 动态库
```
go build -o reqfilter.exe reqfilter\main.go   # 拦截 HTTP 请求，返回自定义内容给 HTTP 客户端
go build -o respfilter.exe respfilter\main.go # 拦截 HTTP 响应，篡改后返回给 HTTP 客户端
go build -o passthru.exe passthru\main.go     # 拦截请求和响应，输出到日志，不做任何篡改
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