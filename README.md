# XRAY CRACKER

### 生成证书

使用 `-g username` 生成永久证书

### Patch Xray
使用 `-c xray_path` 修改xray

## 破解效果

```
H:\xray-crack (master -> origin)
λ go build .

H:\xray-crack (master -> origin)
λ xray-crack.exe -h
Usage of xray-crack.exe:
  -c string
        patch xray，需要指定xray程序文件路径
  -g string
        生成一个永久license，需要指定用户名
  -p string
        解析官方证书，需要指定证书路径

H:\xray-crack (master -> origin)
λ xray-crack.exe -c xray_windows_386.exe
Signature index: 0x92919b
Patch success: xray_windows_386.exe

H:\xray-crack (master -> origin)
λ xray-crack.exe -g Lz1y
temp aes iv: 0f79b747bb60a29c82d8f4da079a767b
证书已写入文件：xray-license.lic

H:\xray-crack (master -> origin)
λ xray_windows_386.exe version

____  ___.________.    ____.   _____.___.
\   \/  /\_   __   \  /  _  \  \__  |   |
 \     /  |    _  _/ /  /_\  \  /   |   |
 /     \  |    |   \/    |    \ \____   |
\___/\  \ |____|   /\____|_   / / _____/
      \_/       \_/        \_/  \/

Version: 1.4.2/d579ba25/COMMUNITY-ADVANCED
Licensed to icorgi, license is valid until 2099-09-09 08:00:00

[xray 1.4.2/d579ba25]
Build: [2020-11-10] [windows/amd64] [RELEASE/COMMUNITY-ADVANCED]
Compiler Version: go version go1.14.4 linux/amd64
License ID: 00000000000000000000000000000000
User Name: icorgi/00000000000000000000000000000000
Not Valid Before: 2020-06-12 00:00:00
Not Valid After: 2099-09-09 08:00:00

To show open source licenses, please use `osslicense` sub-command.
```
