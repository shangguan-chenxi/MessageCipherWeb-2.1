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
