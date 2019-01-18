import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
        import java.security.interfaces.RSAPublicKey;
        import java.security.spec.PKCS8EncodedKeySpec;
        import java.security.spec.X509EncodedKeySpec;
        import java.util.HashMap;
        import java.util.Map;

        import javax.crypto.Cipher;

public class RSACoder extends Object{
    //非对称密钥算法
    public final String KEY_ALGORITHM="RSA";
    private final int KEY_SIZE=1024;
    private String PUBLIC_KEY=null;
    private String PRIVATE_KEY=null;
    Map<String,Object> keyMap = new HashMap<String,Object>();

    public RSACoder() throws NoSuchAlgorithmException {
        //实例化密钥生成器
        KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance(KEY_ALGORITHM);
        //初始化密钥生成器
        keyPairGenerator.initialize(KEY_SIZE);
        //生成密钥对
        KeyPair keyPair=keyPairGenerator.generateKeyPair();
        //甲方公钥
        RSAPublicKey publicKey=(RSAPublicKey) keyPair.getPublic();
        //甲方私钥
        RSAPrivateKey privateKey=(RSAPrivateKey) keyPair.getPrivate();
        //将密钥存储在map中
        this.keyMap.put(PUBLIC_KEY, publicKey);
        this.keyMap.put(PRIVATE_KEY, privateKey);
    }

    public String encryptByPublicKey(String data) throws Exception{
        //实例化密钥工厂
        KeyFactory keyFactory=KeyFactory.getInstance(KEY_ALGORITHM);
        //初始化公钥
        //密钥材料转换
        byte[] key = this.getPublicKey();
        X509EncodedKeySpec x509KeySpec=new X509EncodedKeySpec(key);
        //产生公钥
        PublicKey pubKey= keyFactory.generatePublic(x509KeySpec);
        //数据加密
        Cipher cipher=Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] dataB = data.getBytes();
        byte[] encrypted = cipher.doFinal(dataB);

        return Base64.encode(encrypted);
    }

    public String decryptByPrivateKey(String data) throws Exception{
        //取得私钥
        byte[] key = this.getPrivateKey();
        PKCS8EncodedKeySpec pkcs8KeySpec=new PKCS8EncodedKeySpec(key);
        KeyFactory keyFactory=KeyFactory.getInstance(KEY_ALGORITHM);
        //生成私钥
        PrivateKey privateKey=keyFactory.generatePrivate(pkcs8KeySpec);
        //数据解密
        Cipher cipher=Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] dataB = data.getBytes();

        byte[] decrypted = cipher.doFinal(dataB);
        return Base64.encode(decrypted);

    }

    public String getPrivateKeyS(){
        Key key=(Key)keyMap.get(PRIVATE_KEY);
        return Base64.encode(key.getEncoded());
    }

    public String getPublicKeyS(){
        Key key=(Key)keyMap.get(PUBLIC_KEY);
        return Base64.encode(key.getEncoded());
    }
    public byte[] getPrivateKey(){
        Key key=(Key)this.keyMap.get(PRIVATE_KEY);
        return key.getEncoded();
    }

    public byte[] getPublicKey() throws Exception {
        Key key = (Key) this.keyMap.get(PUBLIC_KEY);
        return key.getEncoded();

    }

//    /**
//     * 私钥解密
//     * @param data 待解密数据
//     * @param key 密钥
//     * @return byte[] 解密数据
//     * */

//
//    public byte[] encryptByPrivateKey(byte[] data,byte[] key) throws Exception{
//
//        //取得私钥
//        PKCS8EncodedKeySpec pkcs8KeySpec=new PKCS8EncodedKeySpec(key);
//        KeyFactory keyFactory=KeyFactory.getInstance(KEY_ALGORITHM);
//        //生成私钥
//        PrivateKey privateKey=keyFactory.generatePrivate(pkcs8KeySpec);
//        //数据加密
//        Cipher cipher=Cipher.getInstance(keyFactory.getAlgorithm());
//        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
//        return cipher.doFinal(data);
//    }
//    /**
//     * 公钥解密
//     * @param data 待解密数据
//     * @param key 密钥
//     * @return byte[] 解密数据
//     * */
//    public byte[] decryptByPublicKey(byte[] data,byte[] key) throws Exception{
//
//        //实例化密钥工厂
//        KeyFactory keyFactory=KeyFactory.getInstance(KEY_ALGORITHM);
//        //初始化公钥
//        //密钥材料转换
//        X509EncodedKeySpec x509KeySpec=new X509EncodedKeySpec(key);
//        //产生公钥
//        PublicKey pubKey=keyFactory.generatePublic(x509KeySpec);
//        //数据解密
//        Cipher cipher=Cipher.getInstance(keyFactory.getAlgorithm());
//        cipher.init(Cipher.DECRYPT_MODE, pubKey);
//        return cipher.doFinal(data);
//    }
}