# MessageCipherWeb-2.1

MessageCipherWeb
  The servlet source code
  NOTE: remember to modify the server RSA keys and AES key before you deploy to server, otherwise all your messages will probably at risk
  RSA Keys located at file: frontEndCrypto.java & AES key located at file: MessageCipher.java
  
 messagecipherwebui
  Vue.js project for Web UI
 
本程序是Web版本的MessageCipher，可脱离TLS进行安全传输，服务器不储存任何信息
（可有效应对网络上对各种即时通讯软件的文字通讯内容的未授权监听）
