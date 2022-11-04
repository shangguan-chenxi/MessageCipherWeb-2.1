package in.chenxi;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import netscape.javascript.JSObject;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;
import java.util.Base64;
import java.util.Base64.Decoder;

import org.apache.tomcat.jakartaee.commons.io.IOUtils;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;


/**
 * Servlet implementation class MessageCipher
 */
public class MessageCipher extends HttpServlet {
	private static final long serialVersionUID = 1L;
	
	private final String GENERAL_ERROR_CODE = "500";
	private final String GENERAL_SUCCESS_CODE = "200";
	private final String FACTAL_ERROR_CODE = "5001";
	private final String CONF_ERROR_CODE = "5002";
	private final boolean DEBUG = false;
	
	private final String GROUP_AES_KRY = ""; // modify this before you deploy it to the server
	private final String STRICT_MODE_AUTH_PWD = ""; // modify this before you deploy it to the server
	private final boolean STRICT_MODE = true; // 严格模式：服务器公钥是否加密。用于对抗中间人攻击， 如开：则返回加密过的服务器公钥
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public MessageCipher() {
        super();
        // TODO Auto-generated constructor stub
    }
    
    private void deliverResponse(HttpServletResponse response, String result, String code) throws IOException {
    	//response.setContentType("application/json;charset=utf-8");
		response.setContentType("application/json");
		response.setCharacterEncoding("UTF-8");
		response.setHeader("Access-Control-Allow-Origin", "*");
		response.setHeader("Access-Control-Allow-Headers", "*");
		response.setHeader("Access-Control-Allow-Methods", "*");
    	PrintWriter writer = response.getWriter();
		writer.write("{\"code\":\"" + code + "\",\"result\":\"" + result + "\",\"strictMode\":\"" + this.STRICT_MODE + "\"}");
		writer.close();
    }
    
    private boolean isValueEmptyOrNull(String str) {
    	return ("".equals(str) || str == null);
    }
    
    private boolean isAesKeyLengthOK(String str) {
    	return str.length() == 16 || str.length() == 24 || str.length() == 32;
    }
    
    /**
     * Java 后端彻底解决跨域问题（CORS）[Servlet方式]
     */
    protected void doOptions(HttpServletRequest request, HttpServletResponse response) {
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Credentials", "true");
        response.setHeader("Access-Control-Allow-Methods", "*");
        response.setHeader("Access-Control-Max-Age", "3600");
        response.setHeader("Access-Control-Allow-Headers", "Authorization,Origin,X-Requested-With,Content-Type,Accept,"
        + "content-Type,origin,x-requested-with,content-type,accept,authorization,token,id,X-Custom-Header,X-Cookie,Connection,User-Agent,Cookie,*");
        response.setHeader("Access-Control-Request-Headers", "Authorization,Origin, X-Requested-With,content-Type,Accept");
        response.setHeader("Access-Control-Expose-Headers", "*");
     }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		//response.getWriter().append("Served at: ").append(request.getContextPath());
		response.setContentType("application/json");
		response.setCharacterEncoding("UTF-8");
		response.setHeader("Access-Control-Allow-Origin", "*");
		response.setHeader("Access-Control-Allow-Headers", "*");
		response.setHeader("Access-Control-Allow-Methods", "*");
		response.getWriter().append("{\"Messsage\":\"GET Method is not supported\",\"code\":\""+ this.GENERAL_ERROR_CODE +"\"}");
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		//doGet(request, response);
		//response.setContentType("application/json;charset=utf-8");
		response.setContentType("application/json");
		response.setCharacterEncoding("UTF-8");
		response.setHeader("Access-Control-Allow-Origin", "*");
		response.setHeader("Access-Control-Allow-Headers", "*");
		response.setHeader("Access-Control-Allow-Methods", "*");
		
        cryptoLib C = new cryptoLib(); // 服务器端的加解密套件
        frontEndCrypto F = new frontEndCrypto(); // 前端和后端共同的加解密套件
        PrintWriter writer = response.getWriter(); // 返回请求的类
        
		// 检查每一个变量：服务器公私钥、身份验证密码、群发密码
        if (this.isValueEmptyOrNull(F.SERVER_RSA_PUBLIC_KEY)) { this.deliverResponse(response, "服务器配置错误：未定义RSA公钥", this.CONF_ERROR_CODE); return; }
        if (this.isValueEmptyOrNull(F.SERVER_RSA_PUBLIC_KEY)) { this.deliverResponse(response, "服务器配置错误：未定义RSA私钥", this.CONF_ERROR_CODE); return; }
        if (this.isValueEmptyOrNull(this.GROUP_AES_KRY) || !this.isAesKeyLengthOK(this.GROUP_AES_KRY)) { this.deliverResponse(response, "服务器配置错误：群组模式密码不符合要求", this.CONF_ERROR_CODE); return; }
        if (this.STRICT_MODE && (this.isValueEmptyOrNull(this.STRICT_MODE_AUTH_PWD) || !this.isAesKeyLengthOK(STRICT_MODE_AUTH_PWD))) { this.deliverResponse(response, "服务器配置错误：STRICT模式的身份验证凭据不符合要求", this.CONF_ERROR_CODE); return; }
        String before = "0123456789ABCDEF", middle = "", after = "";
        try {
			middle = F.encryptByPublicKey(before, F.SERVER_RSA_PUBLIC_KEY);
			after = F.decryptByPrivateKey(middle, F.SERVER_RSA_PRIVATE_KEY);
		} catch (Exception e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			this.deliverResponse(response, "服务器配置错误：请检查服务器RSA密钥对", this.CONF_ERROR_CODE); return;
		} 
        if (!before.equals(after)) { this.deliverResponse(response, "服务器配置错误：RSA密钥对不匹配", this.CONF_ERROR_CODE); return; }
        
		
		/*
		PrintWriter writer = response.getWriter();
		writer.write("{\"Message\":\"You find me!\",\"code\":\"200\"}");
		writer.close();
		*/
		//Map<String, Object> params = new HashMap<String, Object>();
		// 使用 commons-io中 IOUtils 类快速获取输入流内容
        String paramJson = null;
        try {
            paramJson = IOUtils.toString(request.getInputStream(), "UTF-8");
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        if(this.DEBUG) {
        	System.out.println(paramJson);
        }
        requestParams R = JSONObject.parseObject(paramJson, requestParams.class); // 从请求中的json字符串中转换出请求类
        
        String yourRSAPubKey = ""; // 通过保护性AES加解密
		String yourRSAPriKey = ""; // 通过保护性AES加解密
		String itsRSAPubKey = ""; // 通过保护性AES加解密
		String finalCryptText = ""; // 通过保护性AES加解密
		String sector1 = ""; // 对方公钥加密的用于加密通讯密钥的密钥
        String sector2 = ""; // 己方公钥加密的用于加密通讯密钥的密钥
        String sector3 = ""; // 己方私钥对通讯密钥明文的签名
        String sector4 = ""; // 用密钥加密的通讯密钥
        
        String messageAesKey = ""; // 通过保护性AES加解密
        String plainText = ""; // 通过保护性AES加解密
        String encryptedText = ""; // 通过保护性AES加解密
		
		String protectionAesKey = ""; // 保护性AES密码（只能由浏览器生成），就是个随机字符串：被公钥加密的(传输私钥，通讯明文时必须要用它进行加密保护)
        
        try {
        	int i = Integer.parseInt(R.getMethod());
        	
        	// 先检查随机密码
        	if (i != 0) {
	        	protectionAesKey = R.getProtectionAesKey();
	        	if (this.isValueEmptyOrNull(protectionAesKey)) { this.deliverResponse(response, "保护密码不能为空", this.GENERAL_ERROR_CODE); return; }
	        	
	        	protectionAesKey = F.decryptByPrivateKey(protectionAesKey, F.SERVER_RSA_PRIVATE_KEY);
	        	if(this.isValueEmptyOrNull(protectionAesKey)) { this.deliverResponse(response, "服务器无法取得保护密码", this.GENERAL_ERROR_CODE); return; }
	        	if(!this.isAesKeyLengthOK(protectionAesKey)) { this.deliverResponse(response, "保护密码应为16/24/32字符长度", this.GENERAL_ERROR_CODE); return; }
        	}
        	
        	switch (i) {
        		case 0:
        			//返回服务器上的用于前端加解密的RSA公钥
        			if (this.STRICT_MODE) {
        				writer.write("{\"code\":\"" + this.GENERAL_SUCCESS_CODE + "\",\"result\":\"" + F.aesEncrypt(this.STRICT_MODE_AUTH_PWD, this.STRICT_MODE_AUTH_PWD, F.SERVER_RSA_PUBLIC_KEY) + "\",\"authCheckCode\":\"" + F.aesEncrypt(this.STRICT_MODE_AUTH_PWD, this.STRICT_MODE_AUTH_PWD, C.createRandom(true, 6)) + "\",\"strictMode\":\"" + this.STRICT_MODE + "\"}");
        				writer.close();
        			} else {
        				this.deliverResponse(response, F.SERVER_RSA_PUBLIC_KEY, this.GENERAL_SUCCESS_CODE);
        			}
        			break;
        		case 1:
        			// 生成RSA密钥对
        			Map<String, Object> keys = C.initKey();
        			String pubKey = C.getPublicKey(keys);
        			String priKey = C.getPrivateKey(keys);
        			if(this.DEBUG) {
        				System.out.println("RSA公钥 => " + pubKey);
        				System.out.println("RSA私钥 => " + priKey);
        				System.out.println("保护性AES密码 => " + protectionAesKey);
        			}
        			pubKey = F.aesEncrypt(protectionAesKey, protectionAesKey, pubKey);
        			if (this.isValueEmptyOrNull(priKey)) { this.deliverResponse(response, "使用浏览器保护密码加密RSA公钥时出错", this.GENERAL_ERROR_CODE); return; }
    				priKey = F.aesEncrypt(protectionAesKey, protectionAesKey, priKey);
    				if (this.isValueEmptyOrNull(priKey)) { this.deliverResponse(response, "使用浏览器保护密码加密RSA私钥时出错", this.GENERAL_ERROR_CODE); return; }
    				
    				if (this.DEBUG) {
        				System.out.println("前端加密后的RSA私钥 => " + priKey);
        			}
    				
    				writer.write("{\"code\":\"" + this.GENERAL_SUCCESS_CODE + "\",\"publicKey\":\"" + pubKey + "\",\"privateKey\":\"" + priKey + "\"}");
        			writer.close();
        			break;
        			
        		case 2:
        			//生成通讯密码密文
        			yourRSAPubKey = R.getYourRsaPubKey();
        			yourRSAPriKey = R.getYourRsaPriKey();
        			itsRSAPubKey = R.getItsRsaPubKey();
        			messageAesKey = R.getMessageAesKey(); 
        			
        			if(this.isValueEmptyOrNull(yourRSAPubKey)) { this.deliverResponse(response, "需要己方RSA公钥", this.GENERAL_ERROR_CODE); return; }
        			if(this.isValueEmptyOrNull(yourRSAPriKey)) { this.deliverResponse(response, "需要己方RSA私钥", this.GENERAL_ERROR_CODE); return; }
        			if(this.isValueEmptyOrNull(itsRSAPubKey)) { this.deliverResponse(response, "需要对方RSA公钥", this.GENERAL_ERROR_CODE); return; }
        			if(this.isValueEmptyOrNull(messageAesKey)) { this.deliverResponse(response, "通讯密码不能为空", this.GENERAL_ERROR_CODE); return; }
        			
        			messageAesKey = F.aesDecrypt(protectionAesKey, protectionAesKey, messageAesKey);
        			if(this.isValueEmptyOrNull(messageAesKey)) { this.deliverResponse(response, "浏览器解密通讯密码失败", this.GENERAL_ERROR_CODE); return; }
        			if(!this.isAesKeyLengthOK(messageAesKey)) { this.deliverResponse(response, "通讯密码应为16/24/32字符长度", this.GENERAL_ERROR_CODE); return; }
        			
        			yourRSAPubKey = F.aesDecrypt(protectionAesKey, protectionAesKey, yourRSAPubKey);
        			if(this.isValueEmptyOrNull(yourRSAPubKey)) { this.deliverResponse(response, "浏览器解密己方RSA公钥时出错", this.GENERAL_ERROR_CODE); return; }
        			
        			yourRSAPriKey = F.aesDecrypt(protectionAesKey, protectionAesKey, yourRSAPriKey);
        			if(this.isValueEmptyOrNull(yourRSAPriKey)) { this.deliverResponse(response, "浏览器解密己方RSA私钥时出错", this.GENERAL_ERROR_CODE); return; }
        			
        			itsRSAPubKey = F.aesDecrypt(protectionAesKey, protectionAesKey, itsRSAPubKey);
        			if(this.isValueEmptyOrNull(itsRSAPubKey)) { this.deliverResponse(response, "浏览器解密对方RSA公钥时出错", this.GENERAL_ERROR_CODE); return; }
        			
        			if(this.DEBUG) {
        				System.out.println("RSA公钥 => " + yourRSAPubKey);
        				System.out.println("RSA私钥 => " + yourRSAPriKey);
        				System.out.println("对方RSA公钥 => " + itsRSAPubKey);
        				System.out.println("通讯密码 => " + messageAesKey);
        			}
        			
        			String C_protectionAesKey = C.createRandom(false,32); //用于保护通讯密码的随机密码
        			sector1 = C.encryptByPublicKey(C_protectionAesKey, itsRSAPubKey);
        			if(this.isValueEmptyOrNull(sector1)) { this.deliverResponse(response, "用对方RSA公钥加密保护密码时出错", this.GENERAL_ERROR_CODE); return; }
        			
        			sector2 = C.encryptByPublicKey(C_protectionAesKey, yourRSAPubKey);
        			if(this.isValueEmptyOrNull(sector2)) { this.deliverResponse(response, "用己方RSA公钥加密保护密码时出错", this.GENERAL_ERROR_CODE); return; }
        			
        			sector3 = C.sign(C_protectionAesKey, yourRSAPriKey);
        			if(this.isValueEmptyOrNull(sector3)) { this.deliverResponse(response, "用己方RSA私钥对保护密码签名时出错", this.GENERAL_ERROR_CODE); return; }
        			
        			sector4 = C.encrypt(C_protectionAesKey, messageAesKey);
        			if(this.isValueEmptyOrNull(sector4)) { this.deliverResponse(response, "用保护密码加密通讯密码时出错", this.GENERAL_ERROR_CODE); return; }
        			
        			finalCryptText = sector1 + "." + sector2 + "." + sector3 + "." + sector4;
        			finalCryptText = F.aesEncrypt(protectionAesKey, protectionAesKey, finalCryptText);
        			this.deliverResponse(response, finalCryptText, this.GENERAL_SUCCESS_CODE);
        			break;
        			
        		case 3:
        			// 解密通讯密码密文
        			yourRSAPubKey = R.getYourRsaPubKey();
        			yourRSAPriKey = R.getYourRsaPriKey();
        			itsRSAPubKey = R.getItsRsaPubKey();
        			finalCryptText = R.getCryptedMessageAesKey(); // 已用保护性AES密码加密
        			
        			if(this.isValueEmptyOrNull(yourRSAPubKey)) { this.deliverResponse(response, "需要己方RSA公钥", this.GENERAL_ERROR_CODE); return; }
        			if(this.isValueEmptyOrNull(yourRSAPriKey)) { this.deliverResponse(response, "需要己方RSA私钥", this.GENERAL_ERROR_CODE); return; }
        			if(this.isValueEmptyOrNull(itsRSAPubKey)) { this.deliverResponse(response, "需要对方RSA公钥", this.GENERAL_ERROR_CODE); return; }
        			if(this.isValueEmptyOrNull(finalCryptText)) { this.deliverResponse(response, "通讯密码密文不能为空", this.GENERAL_ERROR_CODE); return; }
        			if(this.isValueEmptyOrNull(protectionAesKey)) { this.deliverResponse(response, "保护密码不能为空", this.GENERAL_ERROR_CODE); return; }
        			
        			yourRSAPubKey = F.aesDecrypt(protectionAesKey, protectionAesKey, yourRSAPubKey);
        			if(this.isValueEmptyOrNull(yourRSAPubKey)) { this.deliverResponse(response, "浏览器解密己方RSA公钥时出错", this.GENERAL_ERROR_CODE); return; }
        			
        			yourRSAPriKey = F.aesDecrypt(protectionAesKey, protectionAesKey, yourRSAPriKey);
        			if(this.isValueEmptyOrNull(yourRSAPriKey)) { this.deliverResponse(response, "浏览器解密己方RSA私钥时出错", this.GENERAL_ERROR_CODE); return; }
        			
        			itsRSAPubKey = F.aesDecrypt(protectionAesKey, protectionAesKey, itsRSAPubKey);
        			if(this.isValueEmptyOrNull(itsRSAPubKey)) { this.deliverResponse(response, "浏览器解密对方RSA公钥时出错", this.GENERAL_ERROR_CODE); return; }
        			
        			finalCryptText = F.aesDecrypt(protectionAesKey, protectionAesKey, finalCryptText);
        			if(this.isValueEmptyOrNull(finalCryptText)) { this.deliverResponse(response, "浏览器解密通讯密码密文时出错", this.GENERAL_ERROR_CODE); return; }
        			
        			String[] sectors = finalCryptText.split("\\.");
        			if(sectors.length != 4) { this.deliverResponse(response, "通讯密码密文格式错误", this.GENERAL_ERROR_CODE); return; }
        			
        			// 如果己方私钥能解开第一段RSA密文就可以得到AES密码，也就是对方发来的消息
        			String AESProtectionPwd = C.decryptByPrivateKey(sectors[0], yourRSAPriKey);
        			boolean yourMessage = false;
        			
        			// 这里是己方私钥解不开第一段RSA密文，就解开第二段RSA密文得到AES密码，也就是己方向对方发送的消息
        			if (this.isValueEmptyOrNull(AESProtectionPwd)) {
        				AESProtectionPwd = C.decryptByPrivateKey(sectors[1], yourRSAPriKey);
        				yourMessage = true;
        			}
        			
        			// 如果再解不开，收工回家，报错得了
        			if (this.isValueEmptyOrNull(AESProtectionPwd)){ this.deliverResponse(response, "无法使用己方RSA私钥取得保护密码", this.GENERAL_ERROR_CODE); return; }
        			
        			// 这里肯定是已经获得了AES密码
        	        // AES解密数据 + 检查签名，签名有问题弹框框
        			
        			// 对方发送的，对方公钥验证签名
        			if (!yourMessage) {
        				if (!C.verify(AESProtectionPwd, itsRSAPubKey, sectors[2])) {
        					this.deliverResponse(response, "验证签名失败，保护密码可能被篡改或者由于对方RSA公钥不匹配", this.GENERAL_ERROR_CODE);
        					return;
        				}
        			}
        			
        			messageAesKey = C.decrypt(AESProtectionPwd, sectors[3]);
        			if(this.isValueEmptyOrNull(messageAesKey)) { this.deliverResponse(response, "服务器通讯密码时出错", this.GENERAL_ERROR_CODE); return; }
        			
        			messageAesKey = F.aesEncrypt(protectionAesKey, protectionAesKey, messageAesKey);
        			if(this.isValueEmptyOrNull(messageAesKey)) { this.deliverResponse(response, "浏览器加密通讯密码时出错", this.GENERAL_ERROR_CODE); return; }
        			
        			this.deliverResponse(response, messageAesKey, this.GENERAL_SUCCESS_CODE);
        			break;
        			
        		case 4:
        			// 生成随机通讯密码
        			String newAESPwd = C.createRandom(false, 32);
        			newAESPwd = F.aesEncrypt(protectionAesKey, protectionAesKey, newAESPwd);
        			if(this.isValueEmptyOrNull(newAESPwd)) { this.deliverResponse(response, "浏览器加密通讯密码时出错", this.GENERAL_ERROR_CODE); return; }
        			
        			this.deliverResponse(response, newAESPwd, this.GENERAL_SUCCESS_CODE);
        			break;
        			
        		case 5:
        			// 加密通讯明文
        			messageAesKey = R.getMessageAesKey();
        			plainText = R.getPlainText();
        			if(this.isValueEmptyOrNull(messageAesKey)) { this.deliverResponse(response, "通讯密码不能为空", this.GENERAL_ERROR_CODE); return; }
        			if(this.isValueEmptyOrNull(plainText)) { this.deliverResponse(response, "通讯明文不能为空", this.GENERAL_ERROR_CODE); return; }
        			
        			messageAesKey = F.aesDecrypt(protectionAesKey, protectionAesKey, messageAesKey); // 浏览器解密通讯密码
        			if(this.isValueEmptyOrNull(messageAesKey)) { this.deliverResponse(response, "浏览器无法解密通讯密码", this.GENERAL_ERROR_CODE); return; }
        			if(!this.isAesKeyLengthOK(messageAesKey)) { this.deliverResponse(response, "通讯密码应为16/24/32字符长度", this.GENERAL_ERROR_CODE); return; }
        			
        			plainText = F.aesDecrypt(protectionAesKey, protectionAesKey, plainText); // 保护密码解密通讯明文
        			if(this.isValueEmptyOrNull(plainText)) { this.deliverResponse(response, "浏览器无法解密通讯明文", this.GENERAL_ERROR_CODE); return; }
        			
        			if(this.DEBUG) {
        				System.out.println("使用服务器私钥解密后的通讯密码 :: " + messageAesKey);
        				System.out.println("使用通讯密码解密后的通讯明文 :: " + plainText);
        			}

        			encryptedText = C.encrypt(messageAesKey, plainText);
        			if (this.isValueEmptyOrNull(encryptedText)){ this.deliverResponse(response, "服务器加密通讯密文时出错", this.GENERAL_ERROR_CODE); return; }
        			
        			encryptedText = F.aesEncrypt(protectionAesKey, protectionAesKey, encryptedText);
        			if (this.isValueEmptyOrNull(encryptedText)){ this.deliverResponse(response, "浏览器加密通讯密文时出错", this.GENERAL_ERROR_CODE); return; }
        			
        			this.deliverResponse(response, encryptedText, this.GENERAL_SUCCESS_CODE);
        			break;
        			
        		case 6:
        			// 解密通讯密文
        			messageAesKey =R.getMessageAesKey();
        			encryptedText = R.getCryptedText();
        			
        			if(this.isValueEmptyOrNull(messageAesKey)) { this.deliverResponse(response, "通讯密码不能为空", this.GENERAL_ERROR_CODE); return; }
        			if(this.isValueEmptyOrNull(encryptedText)) { this.deliverResponse(response, "通讯密文不能为空", this.GENERAL_ERROR_CODE); return; }
        			
        			messageAesKey = F.aesDecrypt(protectionAesKey, protectionAesKey, messageAesKey); // 保护密码解密通讯密码
        			if(this.isValueEmptyOrNull(messageAesKey)) { this.deliverResponse(response, "浏览器无法解密通讯密码", this.GENERAL_ERROR_CODE); return; }
        			if(!this.isAesKeyLengthOK(messageAesKey)) { this.deliverResponse(response, "通讯密码应为16/24/32字符长度", this.GENERAL_ERROR_CODE); return; }
        			
        			encryptedText = F.aesDecrypt(protectionAesKey, protectionAesKey, encryptedText); // 保护密码解密通讯密码
        			if(this.isValueEmptyOrNull(encryptedText)) { this.deliverResponse(response, "浏览器无法解密通讯密文", this.GENERAL_ERROR_CODE); return; }
        			
        			if(this.DEBUG) {
        				System.out.println("使用服务器私钥解密后的通讯密码 :: " + messageAesKey);
        				System.out.println("加密的通讯明文 :: " + encryptedText);
        			}
        			
        			plainText = C.decrypt(messageAesKey, encryptedText);
        			if (this.isValueEmptyOrNull(plainText)){ this.deliverResponse(response, "服务器解密通讯密文时出错", this.GENERAL_ERROR_CODE); return; }
        			
        			plainText = F.aesEncrypt(protectionAesKey, protectionAesKey, plainText);
        			if (this.isValueEmptyOrNull(plainText)){ this.deliverResponse(response, "浏览器加密通讯明文时出错", this.GENERAL_ERROR_CODE); return; }
        			
        			this.deliverResponse(response, plainText, this.GENERAL_SUCCESS_CODE);
        			break;
        			
        		case 7:
        			// 群聊模式 加密
        			plainText = R.getPlainText();
        			if(this.isValueEmptyOrNull(plainText)) { this.deliverResponse(response, "通讯明文不能为空", this.GENERAL_ERROR_CODE); return; }
        			
        			plainText = F.aesDecrypt(protectionAesKey, protectionAesKey, plainText);
        			if (this.isValueEmptyOrNull(plainText)){ this.deliverResponse(response, "浏览器解密通讯明文时出错", this.GENERAL_ERROR_CODE); return; }
        			
        			encryptedText = C.encrypt(this.GROUP_AES_KRY, plainText);
        			if (this.isValueEmptyOrNull(encryptedText)){ this.deliverResponse(response, "服务器加密通讯明文时出错", this.GENERAL_ERROR_CODE); return; }
        			
        			encryptedText = F.aesEncrypt(protectionAesKey, protectionAesKey, encryptedText);
        			if (this.isValueEmptyOrNull(encryptedText)){ this.deliverResponse(response, "浏览器加密通讯密文时出错", this.GENERAL_ERROR_CODE); return; }
        			
        			this.deliverResponse(response, encryptedText, this.GENERAL_SUCCESS_CODE);
        			break;
        			
        		case 8:
        			// 群聊模式 解密
        			encryptedText = R.getCryptedText();
        			if(this.isValueEmptyOrNull(encryptedText)) { this.deliverResponse(response, "通讯密文不能为空", this.GENERAL_ERROR_CODE); return; }
        			
        			encryptedText = F.aesDecrypt(protectionAesKey, protectionAesKey, encryptedText);
        			if(this.isValueEmptyOrNull(encryptedText)) { this.deliverResponse(response, "浏览器解密通讯密文时出错", this.GENERAL_ERROR_CODE); return; }
        			
        			plainText = C.decrypt(this.GROUP_AES_KRY, encryptedText);
        			if (this.isValueEmptyOrNull(plainText)){ this.deliverResponse(response, "服务器解密通讯明文时出错", this.GENERAL_ERROR_CODE); return; }
        			
        			plainText = frontEndCrypto.aesEncrypt(protectionAesKey, protectionAesKey, plainText);
        			if (this.isValueEmptyOrNull(plainText)){ this.deliverResponse(response, "浏览器加密通讯明文时出错", this.GENERAL_ERROR_CODE); return; }
        			
        			this.deliverResponse(response, plainText, this.GENERAL_SUCCESS_CODE);
        			break;
        			
        		default:
        			this.deliverResponse(response, "方法未定义", this.GENERAL_ERROR_CODE);
        			break;
        	}
        	writer.close();
        }catch (Exception e) {
        	this.deliverResponse(response, "内部发生严重错误", this.FACTAL_ERROR_CODE);
        	System.out.println(e);
        }
	}

}
