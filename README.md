# MessageCipherWeb-2.1

MessageCipherWeb

  -The servlet source code
  
  -NOTE: remember to modify the server RSA keys and AES key before you deploy to server, otherwise all your messages will probably at risk
  
  -RSA Keys located at file: frontEndCrypto.java & AES key located at file: MessageCipher.java
  
  
 messagecipherwebui
 
  -Vue.js project for Web UI
  
  -NOTE: remember to modify the axios URL before you deploy to server, the axios URL is located at file: main.js
 
本程序是Web版本的MessageCipher，可脱离TLS进行安全传输，服务器不储存任何信息

2.1和2.01的通讯编码互通（PC，Android，Web都使用同一套编码方案）

（MessageCipher可有效应对网络上对各种即时通讯软件的文字通讯内容的未授权监听）

===================

目前版本为Beta版本，因为群收发模式并没做任何身份验证，请谨慎使用该功能

由于后来发现web版本存在重放攻击和中间人攻击的问题，所以web版本重写了一部分，加入了STRICT模式，服务器开启STRICT模式可抵抗中间人和重放攻击（不泄露身份凭据的情况下）

Web Servlet在部署之前要先配置好RSA公钥对（位于文件frontEndCrypto.java），群组密码（位于文件MessageCipher.java），如开启STRICT模式还需要设置验证密码（位于文件MessageCipher.java）

公钥对示例如下

Server RSA公钥 : 
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDycIM3JBa9JvVZX2VWwXYUV35ktTouzNA5W3sO6WpalOK/RjxwlU/YT+ptHS/NxHw+ax9rdrvfLzX3v2Ldkg1y/X+f0b5//yExnnJe4CP1bM3xsnf9YYQ8sHVGvoRyRFC9z6NgIZNahsEn52u/Nn4EN2oscZsCJkKElaIQbtEL8wIDAQAB

Server RSA私钥 : 
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAPJwgzckFr0m9VlfZVbBdhRXfmS1Oi7M0Dlbew7palqU4r9GPHCVT9hP6m0dL83EfD5rH2t2u98vNfe/Yt2SDXL9f5/Rvn//ITGecl7gI/VszfGyd/1hhDywdUa+hHJEUL3Po2Ahk1qGwSfna782fgQ3aixxmwImQoSVohBu0QvzAgMBAAECgYBh3jmaEN99DDUPFwt5si9QluFXFjGeot+Lx/otUty0JFZEkL3lVOEemWQxGA8sKZ1eNTBB2XSN7CkFEiV+/G6gq7kLo4SJUPn61uVY+IyqsOCkg+hRNFKNAYnZp3gobmvCAfJr+cknzj68iEjTejrWpGagL2z7k4rhdZkm9CLUgQJBAP2fSySEq5B6WuhKyAL9K69GtywgP13OHxGWjc4exkKFQlcqrzuRQ9x+N0Ql747C/0SxF+pO9gadLEThKcJTEUsCQQD0tmFAJr1jPYWnNmBPH8omssJWiHZJWG9T3ollRWRqQomBGUM+NSotuGyBeCtvi8ozO7Td3t42puwW5t24ZW75AkAp2WUOy417s5TYi65hP+E7dNG4yEFsexyJTGxtvIo+Y7rEo1hy3c9yzKjV5+SVi/uPHCG0Gf9irACoBPddB1PtAkBg2AyEptAshhxuoEZdCeemiPf/5uFpBWaJenhFa8DhjJN+U9EYvVGD5oiKdFQ8QMY0oFxjsd+fIVAtgBAe+YWBAkEAg2o3JM4eSTFHPZodyEGt+gtsaZge798QleODYzFCQ11MIlEHxrvWstWLjLFUhr8SdAD4zS24zl0EJhzDbR2Lbw==

群组密码示例：1234567890ABCDEF

验证密码示例：1234567890123456

