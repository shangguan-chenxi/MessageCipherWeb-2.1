package in.chenxi;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class frontEndCrypto {

	public frontEndCrypto() {
		// TODO Auto-generated constructor stub
	}

    public static byte[] decryptBASE64(String key) {
        return Base64.getDecoder().decode(key);
    }

    public static String encryptBASE64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

/**
 * RSA部分
 * 
 * 和前端匹配的代码
   
   import JSEncrypt from 'jsencrypt' // for RSA
   .....
   var encryptor = new JSEncrypt({ default_key_size: 1024 })
   encryptor.setPublicKey(this.serverRSAPubKey)
   var serverPubKeyCryptedMessageAesKey = this.encryptByRsaPublicKey(this.serverRSAPubKey, this.requestData.messageAesKey)
   
   encryptByRsaPublicKey (pubKey, data) {
      this.encryptor.setPublicKey(pubKey)
      return this.encryptor.encrypt(data)
    },
    encryptByRsaPrivateKey (priKey, data) {
      this.encryptor.setPrivateKey(priKey)
      return this.encryptor.encrypt(data)
    },
    decryptByRsaPublicKey (pubKey, data) {
      this.encryptor.setPublicKey(pubKey)
      return this.encryptor.decrypt(data)
    },
    decryptByRsaPrivateKey (priKey, data) {
      this.encryptor.setPrivateKey(priKey)
      return this.encryptor.decrypt(data)
    },
 */
    // modify these before you deploy it to the server
	public static final String SERVER_RSA_PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDycIM3JBa9JvVZX2VWwXYUV35ktTouzNA5W3sO6WpalOK/RjxwlU/YT+ptHS/NxHw+ax9rdrvfLzX3v2Ldkg1y/X+f0b5//yExnnJe4CP1bM3xsnf9YYQ8sHVGvoRyRFC9z6NgIZNahsEn52u/Nn4EN2oscZsCJkKElaIQbtEL8wIDAQAB";
	public static final String SERVER_RSA_PRIVATE_KEY = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAPJwgzckFr0m9VlfZVbBdhRXfmS1Oi7M0Dlbew7palqU4r9GPHCVT9hP6m0dL83EfD5rH2t2u98vNfe/Yt2SDXL9f5/Rvn//ITGecl7gI/VszfGyd/1hhDywdUa+hHJEUL3Po2Ahk1qGwSfna782fgQ3aixxmwImQoSVohBu0QvzAgMBAAECgYBh3jmaEN99DDUPFwt5si9QluFXFjGeot+Lx/otUty0JFZEkL3lVOEemWQxGA8sKZ1eNTBB2XSN7CkFEiV+/G6gq7kLo4SJUPn61uVY+IyqsOCkg+hRNFKNAYnZp3gobmvCAfJr+cknzj68iEjTejrWpGagL2z7k4rhdZkm9CLUgQJBAP2fSySEq5B6WuhKyAL9K69GtywgP13OHxGWjc4exkKFQlcqrzuRQ9x+N0Ql747C/0SxF+pO9gadLEThKcJTEUsCQQD0tmFAJr1jPYWnNmBPH8omssJWiHZJWG9T3ollRWRqQomBGUM+NSotuGyBeCtvi8ozO7Td3t42puwW5t24ZW75AkAp2WUOy417s5TYi65hP+E7dNG4yEFsexyJTGxtvIo+Y7rEo1hy3c9yzKjV5+SVi/uPHCG0Gf9irACoBPddB1PtAkBg2AyEptAshhxuoEZdCeemiPf/5uFpBWaJenhFa8DhjJN+U9EYvVGD5oiKdFQ8QMY0oFxjsd+fIVAtgBAe+YWBAkEAg2o3JM4eSTFHPZodyEGt+gtsaZge798QleODYzFCQ11MIlEHxrvWstWLjLFUhr8SdAD4zS24zl0EJhzDbR2Lbw==";
	public static final String KEY_ALGORITHM = "RSA";
    public static final String SIGNATURE_ALGORITHM = "MD5withRSA";

    private static final String PUBLIC_KEY = "RSAPublicKey";
    private static final String PRIVATE_KEY = "RSAPrivateKey";

    /**
     * 用私钥对信息生成数字签名
     *
     * @param data
     *            加密数据
     * @param privateKey
     *            私钥
     * @return
     * @throws Exception
     */
    public static String sign(byte[] data, String privateKey) throws Exception {
    	try {
	        // 解密由base64编码的私钥
	        byte[] keyBytes = decryptBASE64(privateKey);
	        // 构造PKCS8EncodedKeySpec对象
	        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
	        // KEY_ALGORITHM 指定的加密算法
	        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
	        // 取私钥匙对象
	        PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);
	        // 用私钥对信息生成数字签名
	        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
	        signature.initSign(priKey);
	        signature.update(data);
	        return encryptBASE64(signature.sign());
    	}catch(Exception e) {
    		e.printStackTrace();
    		return "";
    	}
    }

    /**
     * 校验数字签名
     *
     * @param data
     *            加密数据
     * @param publicKey
     *            公钥
     * @param sign
     *            数字签名
     * @return 校验成功返回true 失败返回false
     * @throws Exception
     */
    public static boolean verify(byte[] data, String publicKey, String sign) throws Exception {
    	try {
	        // 解密由base64编码的公钥
	        byte[] keyBytes = decryptBASE64(publicKey);
	        // 构造X509EncodedKeySpec对象
	        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
	        // KEY_ALGORITHM 指定的加密算法
	        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
	        // 取公钥匙对象
	        PublicKey pubKey = keyFactory.generatePublic(keySpec);
	        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
	        signature.initVerify(pubKey);
	        signature.update(data);
	        // 验证签名是否正常
	        return signature.verify(decryptBASE64(sign));
    	} catch(Exception e) {
    		e.printStackTrace();
    		return false;
    	}
    }

    public static String decryptByPrivateKey(String data, String key) throws Exception {
    	try {
	        // 对密钥解密
	        byte[] keyBytes = decryptBASE64(key);
	        // 取得私钥
	        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
	        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
	        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
	        // 对数据解密
	        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
	        cipher.init(Cipher.DECRYPT_MODE, privateKey);
	        return new String(cipher.doFinal(decryptBASE64(data)));
    	} catch(Exception e) {
    		e.printStackTrace();
    		return "";
    	}
    }

    /**
     * 解密<br>
     * 用私钥解密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    /*
    public static byte[] decryptByPrivateKey(String data, String key) throws Exception {
    	try {
        return decryptByPrivateKey(decryptBASE64(data), key);
    	} catch(Exception e) {
    		return "".getBytes();
    	}
    }
    */

    /**
     * 解密<br>
     * 用公钥解密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static String decryptByPublicKey(String data, String key) throws Exception {
    	try {
	        // 对密钥解密
	        byte[] keyBytes = decryptBASE64(key);
	        // 取得公钥
	        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
	        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
	        Key publicKey = keyFactory.generatePublic(x509KeySpec);
	        // 对数据解密
	        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
	        cipher.init(Cipher.DECRYPT_MODE, publicKey);
	        return new String(cipher.doFinal(decryptBASE64(data)));
    	} catch(Exception e) {
    		e.printStackTrace();
    		return "";
    	}
    }

    /**
     * 加密<br>
     * 用公钥加密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static String encryptByPublicKey(String data, String key) throws Exception {
	    try {
	        // 对公钥解密
	        byte[] keyBytes = decryptBASE64(key);
	        // 取得公钥
	        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
	        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
	        Key publicKey = keyFactory.generatePublic(x509KeySpec);
	        // 对数据加密
	        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
	        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
	        return encryptBASE64(cipher.doFinal(data.getBytes()));
    	} catch(Exception e) {
    		e.printStackTrace();
    		return "";
    	}
    }

    /**
     * 加密<br>
     * 用私钥加密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static String encryptByPrivateKey(String data, String key) throws Exception {
    	try {
	        // 对密钥解密
	        byte[] keyBytes = decryptBASE64(key);
	        // 取得私钥
	        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
	        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
	        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
	        // 对数据加密
	        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
	        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
	        return encryptBASE64(cipher.doFinal(decryptBASE64(data)));
    	} catch(Exception e) {
    		e.printStackTrace();
    		return "";
    	}
    }

    /**
     * 取得私钥
     *
     * @param keyMap
     * @return
     * @throws Exception
     */
    public static String getPrivateKey(Map<String, Key> keyMap) throws Exception {
        Key key = (Key) keyMap.get(PRIVATE_KEY);
        return encryptBASE64(key.getEncoded());
    }

    /**
     * 取得公钥
     *
     * @param keyMap
     * @return
     * @throws Exception
     */
    public static String getPublicKey(Map<String, Key> keyMap) throws Exception {
        Key key = keyMap.get(PUBLIC_KEY);
        return encryptBASE64(key.getEncoded());
    }

    /**
     * 初始化密钥
     *
     * @return
     * @throws Exception
     */
    public static Map<String, Key> initKey() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator
                .getInstance(KEY_ALGORITHM);
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        Map<String, Key> keyMap = new HashMap(2);
        keyMap.put(PUBLIC_KEY, keyPair.getPublic());// 公钥
        keyMap.put(PRIVATE_KEY, keyPair.getPrivate());// 私钥
        return keyMap;
    }
    
    
    /**
     * AES部分
     * 
     * 和前端匹配的代码
       
    import CryptoJS from 'crypto-js' // for AES
    ......
    encryptByAesKey (aesKey, iv, data) {
      var key = CryptoJS.enc.Utf8.parse(aesKey)
      var IV = CryptoJS.enc.Utf8.parse(iv.substring(0, 16))
      var encrypted = CryptoJS.AES.encrypt(data, key, { iv: IV, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 })
      return encrypted.toString()
    },
    decryptByAesKey (aesKey, iv, data) {
      // var key = CryptoJS.enc.Hex.parse(aesKey)
      // var IV = CryptoJS.enc.Hex.parse(iv.substring(0, 16))
      var key = CryptoJS.enc.Utf8.parse(aesKey)
      var IV = CryptoJS.enc.Utf8.parse(iv.substring(0, 16))
      var decrypted = CryptoJS.AES.decrypt(data, key, { iv: IV, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 })
      return decrypted.toString()
    },
     */

    public static String aesDecrypt(String key, String IV, String cipherStr) {
        IvParameterSpec iv = new IvParameterSpec(IV.substring(0, 16).getBytes());
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        try {
        	Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            //Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
            return new String(cipher.doFinal(decryptBASE64(cipherStr)), StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }
    
    public static String aesEncrypt(String key, String IV, String data) {
        IvParameterSpec iv = new IvParameterSpec(IV.substring(0, 16).getBytes());
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        try {
        	Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            //Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
            return encryptBASE64(cipher.doFinal(data.getBytes()));
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }
    
    /*
    public static void main(String[] args) throws Exception {
        String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCwjDm1HXDw8QH5ZtGMQIl2h/I8E+chOQA8aQ8xCR/+aHnROaN/ZU5Vmd2Zz7g6cAacR9BSm60+iSCYtvEGJKl0WqvbPGJkc8tedjNF1QqgWqkkuE6Udgw2OkEKJCxDg6PrAniR7Cc0io9G8bW4P8JDJjSbbafvMPDDFbVVUWJxxwIDAQAB";
        String privateKey = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALCMObUdcPDxAflm0YxAiXaH8jwT5yE5ADxpDzEJH/5oedE5o39lTlWZ3ZnPuDpwBpxH0FKbrT6JIJi28QYkqXRaq9s8YmRzy152M0XVCqBaqSS4TpR2DDY6QQokLEODo+sCeJHsJzSKj0bxtbg/wkMmNJttp+8w8MMVtVVRYnHHAgMBAAECgYAOLuW/8CKPqL0A3Uq+WrzwYdGLFApAeATV1Zbb2KDSXnBS56+D346gf+D2p2Jkh3VwfrB0wn7zhC6zNhc86BsY1K6Q7xU8b7asDBqki48H3ExuxjEosEqUdLf9p9pPBCPI3I4CN/EZPEoFjNRNi5ZX/CY4iaOgsXPHEkcxuW3GQQJBAOBo9UpXesZYCsmuuGN5SOy6tXI613NUBvXKXkxBil3ZOqozlaSjv5NSQb2zLeh2DcYfecumfgn04rNM/pLeDmECQQDJZnXWg4VrXdjc9hqu/8rkmxdhsr3ERkX1uKJrDUB+AOdFs6mS9gEHnJ70zqQ2ucbhQ4htulbLc9pBVL5gy+EnAkEArdhhfa/7SsBVyxvxeA4zMkEJ4242Df/gTHTzTDvRxxZL3iKMILlB5gzpJN40CEu8K+miXuOh7HCrVp+k733awQJBAMDkERhS/wXF7F40l3nkIz6wC8TWnEnPxFGDdItzNcF4vAhV+qN2WaYgq11sTHrdk01MkO4G+foCC5dmwq+SlSECQGm58ReqUTRDAKl32VX0vEdVvOj2getVxW6jQjJFiGj8iNDfK+DpiLfns3YjwSlWHGxHz1S6/lQ+58+M+fEyvUs=";

        String inputStr = "sign";
        byte[] data = inputStr.getBytes();

        byte[] encodedData = RSACode.encryptByPrivateKey(data, privateKey);

        byte[] decodedData = RSACode
                .decryptByPrivateKey(decryptBASE64("mIENuMEvbTkceKAzoqDLx8qiuZ12wZ5eRhZMKf2dfL+ZJkxJHnBXxNZiMpbIFHjIJSoP7sBxknR8PEPFAVgNoL2HqlEmOGFzpXugWK37fDpoKSOFpT0AKJyY4/j87F52YZlIjsJgk74+KDyrPKxagzEZejb8bAI4Ln/54UaVhd0="),
                        privateKey);
        String outputStr = new String(decodedData);
        System.err.println("加密前: " + inputStr + "\n\r" + "解密后: " + outputStr);

        System.err.println("私钥签名——公钥验证签名");
        // 产生签名
        String sign = RSACode.sign(encodedData, privateKey);
        System.err.println("签名:" + sign);
        // 验证签名
        boolean status = RSACode.verify(encodedData, publicKey, sign);
        System.err.println("状态:" + status);
        
        // 前后端通用的RSA密钥
        Map<String, Key> Keys = frontBackCrypto.initKey();
        System.err.println("Client RSA公钥 : " + frontBackCrypto.getPublicKey(Keys));
        System.err.println("Client RSA私钥 : " + frontBackCrypto.getPrivateKey(Keys));
        
        Keys = frontBackCrypto.initKey();
        System.err.println("Server RSA公钥 : " + frontBackCrypto.getPublicKey(Keys));
        System.err.println("Server RSA私钥 : " + frontBackCrypto.getPrivateKey(Keys));
    }
    */

}
