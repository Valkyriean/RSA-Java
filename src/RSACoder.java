import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import sun.misc.BASE64Decoder;

import javax.crypto.Cipher;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

public class RSACoder extends Object{
    //非对称密钥算法
    public final String KEY_ALGORITHM="RSA";
    /**
     * 密钥长度，DH算法的默认密钥长度是1024
     * 密钥长度必须是64的倍数，在512到65536位之间
     * */
    private final int KEY_SIZE=512;
    //公钥
    private byte[] PUBLIC_KEY=null;
    //私钥
    private byte[] PRIVATE_KEY=null;


    public RSACoder() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KEY_ALGORITHM);
//        设定密匙长度 默认1024
        kpg.initialize(KEY_SIZE);
        KeyPair keyPair = kpg.generateKeyPair();
        PUBLIC_KEY = keyPair.getPublic().getEncoded();
        PRIVATE_KEY = keyPair.getPrivate().getEncoded();
    }

    public String encryptByPublicKey(String data) throws Exception{
        //实例化密钥工厂
        KeyFactory keyFactory=KeyFactory.getInstance(KEY_ALGORITHM);
        //初始化公钥
        //密钥材料转换
        X509EncodedKeySpec x509KeySpec=new X509EncodedKeySpec(PUBLIC_KEY);
        //产生公钥
        PublicKey pubKey=keyFactory.generatePublic(x509KeySpec);
        //数据加密
        Cipher cipher=Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        return Base64.encode(cipher.doFinal((new BASE64Decoder()).decodeBuffer(data)));
    }

    public String decryptByPrivateKey(String data) throws Exception{
        //取得私钥
        PKCS8EncodedKeySpec pkcs8KeySpec=new PKCS8EncodedKeySpec(PRIVATE_KEY);
        KeyFactory keyFactory=KeyFactory.getInstance(KEY_ALGORITHM);
        //生成私钥
        PrivateKey privateKey=keyFactory.generatePrivate(pkcs8KeySpec);
        //数据解密
        Cipher cipher=Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return Base64.encode(cipher.doFinal((new BASE64Decoder()).decodeBuffer(data)));

    }

    public String getPrivateKey(){
        return Base64.encode(PRIVATE_KEY);
    }

    public String getPublicKey(){
        return Base64.encode(PUBLIC_KEY);
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