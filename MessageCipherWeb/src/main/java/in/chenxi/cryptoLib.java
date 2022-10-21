package in.chenxi;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.swing.JOptionPane;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
//import javax.xml.bind.DatatypeConverter;

public class cryptoLib {
	
	cryptoLib () {}
	
	
	/*
    输入：byte[]
    输出：String
    */
    public static String byteToHex(byte[] key) {
        // Base64编码
        try{
            //String str = Base64.getEncoder().encodeToString(key);
            //String str = (new BASE64Encoder()).encodeBuffer(key); // 与Android编码同步的正确方式
            //return str;
            String strHex = "";
            StringBuilder sb = new StringBuilder("");
            for (int n = 0; n < key.length; n++) {
                strHex = Integer.toHexString(key[n] & 0xFF);
                sb.append((strHex.length() == 1) ? "0" + strHex : strHex); // 每个字节由两个字符表示，位数不够，高位补0
            }
            return sb.toString().toUpperCase().trim();
        }catch(Exception e){
            return "Encode Error";
        }
    }

    /*
    输入：String
    输出：byte[]
    */
    public static byte[] hexToByte(String key) {
        // Base64解码
        try{
            //byte[] bt = Base64.getDecoder().decode(key);
            //byte[] bt = (new BASE64Decoder()).decodeBuffer(key); // 与Android编码同步的正确方式
            //return bt;
            int m = 0, n = 0;
            int byteLen = key.length() / 2; // 每两个字符描述一个字节
            byte[] ret = new byte[byteLen];
            for (int i = 0; i < byteLen; i++) {
                m = i * 2 + 1;
                n = m + 1;
                int intVal = Integer.decode("0x" + key.substring(i * 2, m) + key.substring(m, n));
                ret[i] = Byte.valueOf((byte)intVal);
            }
            return ret;
        }catch(Exception e){
            String err = "Decode Error";
            return err.getBytes();
        }
    }
    
    /*
    * 生成指定长度的随机字符串
    *
    * @param numberFlag:是否为纯数字
    * @param length:生成的字符串的长度
    * 
    * @return String
    */
    public static String createRandom(boolean numberFlag, int length){  
        String retStr = "";  
        String strTable = numberFlag ? "1234567890" : "`1234567890-=abcdefghijklmnopqrstuvwxyz~!@#$%^&*()_+[]{}ABCDEFGHIJKLMNOPQRSTUVWXYZ;:,./<>?\\\"";  
        int len = strTable.length();  
        boolean bDone = true;  
        do {  
            retStr = "";  
            int count = 0;  
            for (int i = 0; i < length; i++) {  
                double dblR = Math.random() * len;  
                int intR = (int) Math.floor(dblR);  
                char c = strTable.charAt(intR);  
                if (('0' <= c) && (c <= '9')) {  
                    count++;  
                }  
                retStr += strTable.charAt(intR);  
            }  
            if (count >= 2) {  
                bDone = false;  
            }  
        } while (bDone);  
        return retStr;  
    }
    
    /*
    AES 部分
    */
    
    //private static final String CipherMode = "AES/ECB/PKCS5Padding";//使用ECB加密，不需要设置IV，但是不安全
    private static final String CipherMode = "AES/CFB/NoPadding";//使用CFB加密，需要设置IV

    /**
     * 对字符串加密
     *
     * @param key  密钥
     * @param data 源字符串
     * @return 加密后的字符串
     */
    public static String encrypt(String key, String data){
        try {
            Cipher cipher = Cipher.getInstance(CipherMode);
            SecretKeySpec keyspec = new SecretKeySpec(key.getBytes(), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, keyspec, new IvParameterSpec(
                    new byte[cipher.getBlockSize()]));
            byte[] encrypted = cipher.doFinal(data.getBytes("utf-8"));
            //return Base64.encodeToString(encrypted, Base64.DEFAULT);
            //return Base64.getEncoder().encodeToString(encrypted); // OK
            return byteToHex(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    /**
     * 对字符串解密
     *
     * @param key  密钥
     * @param data 已被加密的字符串
     * @return 解密得到的字符串
     */
    public static String decrypt(String key, String data){
        try {
            //byte[] encrypted1 = Base64.decode(data.getBytes());
            Cipher cipher = Cipher.getInstance(CipherMode);
            SecretKeySpec keyspec = new SecretKeySpec(key.getBytes(), "AES");
            cipher.init(Cipher.DECRYPT_MODE, keyspec, new IvParameterSpec(
                    new byte[cipher.getBlockSize()]));
            //byte[] original = cipher.doFinal(encrypted1);
            byte[] original = cipher.doFinal(hexToByte(data));
            //byte[] original = cipher.doFinal(Base64.getDecoder().decode(data));
            return new String(original,"utf-8");
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }
    
    
    /*
    RSA 部分
    */
    
    public static final String KEY_ALGORITHM = "RSA";
    //android系统的RSA实现是"RSA/None/NoPadding"，而标准JDK实现是"RSA/None/PKCS1Padding"
    public static final String ECB_PKCS1_PADDING = "RSA/ECB/PKCS1Padding";//加密填充方式 "RSA/ECB/PKCS1Padding"
    public static final String SIGNATURE_ALGORITHM = "MD5withRSA";
 
    private static final String PUBLIC_KEY = "RSAPublicKey";
    private static final String PRIVATE_KEY = "RSAPrivateKey";
    
    /**
     * 初始化密钥
     *
     * @return
     */
    public static Map<String, Object> initKey(){
        try {
            // RSA算法要求有一个可信任的随机数源
            SecureRandom secureRandom = new SecureRandom();
            
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
            //keyPairGen.initialize(2048);
            keyPairGen.initialize(2048, secureRandom);
            KeyPair keyPair = keyPairGen.generateKeyPair();
            // 公钥
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            // 私钥
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

            //System.out.println(encodeBASE64(publicKey.getEncoded()));
            //System.out.println(encodeBASE64(privateKey.getEncoded()));
            
            Map<String, Object> keyMap = new HashMap<String, Object>(2);
            keyMap.put(PUBLIC_KEY, publicKey);
            keyMap.put(PRIVATE_KEY, privateKey);
            //System.out.println("密钥生成完毕");
            return keyMap;
            
        }catch(Exception e){
            //System.out.println("密钥生成失败");
            return null;
        }
    }
    
    
    /**
     * 取得私钥
     *
     * @param keyMap
     * @return
     */
    public static String getPrivateKey(Map<String, Object> keyMap){
        try{
            Key key = (Key) keyMap.get(PRIVATE_KEY);
            //(new BASE64Encoder()).encodeBuffer(keyBytes);(new BASE64Decoder()).decodeBuffer(data); ?? Base64.getEncoder().encodeToString(key);
            return byteToHex(key.getEncoded()); //v1
            //return Base64.getEncoder().encodeToString(key.getEncoded()); // v2
        }catch(Exception e){
            return "";
        }
    }
    
    /**
     * 取得公钥
     *
     * @param keyMap
     * @return
     */
    public static String getPublicKey(Map<String, Object> keyMap){
        try{
            Key key = (Key) keyMap.get(PUBLIC_KEY);
            return byteToHex(key.getEncoded()); //v1
            //return Base64.getEncoder().encodeToString(key.getEncoded()); // v2
        }catch(Exception e){
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
     */
    public static String encryptByPrivateKey(String data, String key){
        try{
            // 对密钥解密
            byte[] keyBytes = hexToByte(key);
            //byte[] keyBytes = (new BASE64Decoder()).decodeBuffer(key); // 正确方式
            
            // 取得私钥
            PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
            
            // 对数据加密
            //Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
            Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            
            //byte[] bytes = cipher.doFinal(data.getBytes());
            byte[] bytes = cipher.doFinal(data.getBytes("utf-8"));
            //byte[] bytes = cipher.doFinal((new BASE64Decoder()).decodeBuffer(data)); // 正确方式
            
            String result = byteToHex(bytes);
            
            //System.out.println("私钥加密数据正常");
            
            return result;
        }catch(Exception e){
            //System.out.println("私钥加密数据异常");
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
     */
    public static String decryptByPrivateKey(String data, String key){
        try {
        	byte[] keyBytes = hexToByte(key);
            //byte[] keyBytes = (new BASE64Decoder()).decodeBuffer(key); // 正确方式
 
            // 取得私钥
            PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
 
            // 对数据解密
            //Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
            Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
 
            byte[] original = cipher.doFinal(hexToByte(data));
            //byte[] original = cipher.doFinal((new BASE64Decoder()).decodeBuffer(data)); // 正确方式
            String result = new String(original,"utf-8");
            
            //System.out.println("私钥解密数据正常");
            
            return result;
        }catch(Exception e){
            //System.out.println("私钥解密数据异常");
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
     */
    public static String encryptByPublicKey(String data, String key){
        try{
            // 对公钥解密
            byte[] keyBytes = hexToByte(key);
            //byte[] keyBytes = (new BASE64Decoder()).decodeBuffer(key); // 正确方式
            
            // 取得公钥
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            Key publicKey = keyFactory.generatePublic(x509KeySpec);
            // 对数据加密
            //Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
            Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            
            //byte[] bytes = cipher.doFinal(data.getBytes());
            byte[] bytes = cipher.doFinal(data.getBytes("utf-8"));
            //byte[] original = cipher.doFinal((new BASE64Decoder()).decodeBuffer(data)); // 正确方式
            
            String result = byteToHex(bytes);
            
            //System.out.println("公钥加密数据正常");
            
            return result;
        }catch(Exception e){
            //System.out.println("公钥加密数据异常");
            e.printStackTrace(); 
            return "";
        }
    }
    
    /**
     * 解密<br>
     * 用公钥解密
     *
     * @param data
     * @param key
     */
    public static String decryptByPublicKey(String data, String key){
        try{
            // 对密钥解码
            byte[] keyBytes = hexToByte(key);
            //byte[] keyBytes = (new BASE64Decoder()).decodeBuffer(key); // 正确方式
            
            // 取得公钥
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            Key publicKey = keyFactory.generatePublic(x509KeySpec);
                
            // 解密数据
            //Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
            Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            
            byte[] bytes = cipher.doFinal(hexToByte(data));
            //byte[] bytes = cipher.doFinal((new BASE64Decoder()).decodeBuffer(data)); // 正确方式
            
            String result = new String(bytes, "utf-8");
            
            //System.out.println("公钥解密数据正常");
            
            // 返回解密后的数据
            return result;
        }catch(Exception e){
            //System.out.println("公钥解密数据异常");
            e.printStackTrace(); 
            return "";
        }
    }
    
    /**
     * 用私钥对信息生成数字签名
     *
     * @param data       加密数据
     * @param privateKey 私钥
     * @return
     */
    public static String sign(String data, String privateKey){
        try{
            // 解密由base64编码的私钥
            byte[] keyBytes = hexToByte(privateKey);
            //byte[] keyBytes = (new BASE64Decoder()).decodeBuffer(key); // 正确方式
            
            // 构造PKCS8EncodedKeySpec对象
            PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
 
            // KEY_ALGORITHM 指定的加密算法
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
 
            // 取私钥匙对象
            PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);
            
            // 用私钥对信息生成数字签名
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initSign(priKey);
            //signature.update(data.getBytes());
            signature.update(data.getBytes("utf-8"));
            
            //System.out.println("签名正常");
            
            return byteToHex(signature.sign()); // v1
            //return Base64.getEncoder().encodeToString(signature.sign()); //v2
        }catch(Exception e){
            //System.out.println("签名异常");
            e.printStackTrace(); 
            return "";
        }
    }
    
    /**
     * 校验数字签名
     *
     * @param data      加密数据
     * @param publicKey 公钥
     * @param sign      数字签名
     * @return 校验成功返回true 失败返回false
     */
    public static boolean verify(String data, String publicKey, String sign){
        try{
            // 解密由base64编码的公钥
            byte[] keyBytes = hexToByte(publicKey);
            //byte[] keyBytes = (new BASE64Decoder()).decodeBuffer(publicKey); // 正确方式
            
            // 构造X509EncodedKeySpec对象
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
 
            // KEY_ALGORITHM 指定的加密算法
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
 
            // 取公钥匙对象
            PublicKey pubKey = keyFactory.generatePublic(keySpec);
 
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initVerify(pubKey);
            signature.update(data.getBytes());
            //signature.update(data.getBytes("utf-8"));
            
            //System.out.println("验证签名正常");
            
            // 验证签名是否正常
            //byte[] original = cipher.doFinal((new BASE64Decoder()).decodeBuffer(data)); // 正确方式
            //(new BASE64Encoder()).encodeBuffer(keyBytes);(new BASE64Decoder()).decodeBuffer(data);
            
            return signature.verify(hexToByte(sign));
            //return signature.verify(Base64.getDecoder().decode(sign.getBytes("utf-8")));
            //return signature.verify((new BASE64Decoder()).decodeBuffer(sign)); // OK
        }catch(Exception e){
            //System.out.println("验证签名异常");
            e.printStackTrace(); 
            return false;
        }
    }
}
