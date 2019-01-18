import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import sun.misc.BASE64Decoder;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class backend {
    public static final String KEY_ALGORITHM="RSA";
    private static final int KEY_SIZE=1024;



    public static void main (String[] args) throws Exception {

        //初始化
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KEY_ALGORITHM);
//        设定密匙长度 默认1024
        kpg.initialize(KEY_SIZE);
        KeyPair keyPair = kpg.generateKeyPair();


        byte[] publicKey = keyPair.getPublic().getEncoded();
        byte[] privateKey = keyPair.getPrivate().getEncoded();
        //可视化处理
        String publicKeyDisp = Base64.encode(publicKey);
//        String privateKeyDisp = Base64.encode(privateKey);
//
//        String encoded = "eNqcxvqSKku3Hljluz97wQ1UJOcRFjX7DlG1DpT9ycEODzq5EsL8s6VadfcHnrBAbIWDkXBqvvSjTTUvxE5uNqnZwd8vFdBIgcB6cSqjGfRm8LRLPVXJP98/KEdWCaQIIsJra/wFKiC2yLRWsuWXebEShpes324Ar2e34Tq67jE=";
//        String privatekee = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAIRBMHnal4x9IaU4+70YsDDhoxOrp1Y0RNq7PPy0eW+9Fqi9y3FJ5Uvc6080azHBbLJiTVEv1r0t2oJ2UPD9Fu9QLf10bkW2IZxDnNvj4xEoXXaExfAKAaTVEeqWAqwfHkwLGIEh2tPhCfTUCt1rkH1WGvFj37rHvLI4JHtWzL/nAgMBAAECgYBFKVIQZx+ZeFZ/8Ky01pRM+7IsNzfq/KqFOCVMgZR/uoJ++8HIHLysT3s+kEr+WghdwMpuCnZht/jtALKTU8cJ3l+NyoPp++Ltfzc0Cuc/aU5Ij0mV/rGWK9+1EEROzgD8lPyz7rwnpMMh3XiziQEitlHXXZtXWDUWuElqAq0sAQJBAMB2GsiZ4eAzHfnLSpkAOVlPsqnc7lsOoYm06rhzfMurSsrACl29uW3jNH3Bk5RayOETuq/KujlaAonXFdPOavECQQCv6rUuNQsoTNbzu6wMS7MdHSsiPoobaWpVt5WeBvH/bp+QOzxbibG/j2WAZV3oBsSJMS4416d9zLQfXK1efOhXAkA9qVk5bfvtPdNbxaMX0/eLwroGLA99wvlESl9tSyrvgejLfq2TjQaMy1907wEeZdu4KP8F9VimqUzo5q1Kl/axAkAiYTRXe3ZawemgaKUPIhw3LGQppR9IjCmD5wUOhTz2NqBoh6scGKTsUxH7LdRUbD4ssbfe1Aafx0nMd0hKlw6xAkAVHxIeWPWb/wCGnqBxHmqE5ocDoYLwA/oJRLh0uo7Ie4zVpNgiz2zaPXUfhXUKn5p1rCbKhEfq4W/Zh1Szxodn";
//        String text = "987654321";

//        System.out.println("----------------------------- Public Key -----------------------------");
//        System.out.println(publicKeyDisp);
//        System.out.println("----------------------------- Private Key -----------------------------");
//        System.out.println(privateKeyDisp);




        byte[] publicKey2 = keyPair.getPublic().getEncoded();
        byte[] privateKey2 = keyPair.getPrivate().getEncoded();
        //可视化处理
        String publicKeyDisp2 = Base64.encode(publicKey2);
        String privateKeyDisp2 = Base64.encode(privateKey2);

        String text = "987654321";

        System.out.println("----------------------------- Public Key -----------------------------");
        System.out.println(publicKeyDisp2);
        System.out.println("----------------------------- Private Key -----------------------------");
        System.out.println(privateKeyDisp2);
//
        //数据加密

        byte[] encoded = encryptByPublicKey(text.getBytes(),publicKey);
        String encodedDisp = Base64.encode(encoded);
        System.out.println("----------------------------- Encoded -----------------------------");
        System.out.println(encodedDisp);


        byte[] decoded = decryptByPrivateKey(encoded,privateKey);
        String decodedDisp = new String(decoded);
        System.out.println("----------------------------- Decoded -----------------------------");
        System.out.println(decodedDisp);
    }
    /**
     * 公钥加密
     * @param data
     * @param key 密钥
     * @return byte[] 加密数据
     * */
    public static byte[] encryptByPublicKey(byte[] data,byte[] key) throws Exception{

        //实例化密钥工厂
        KeyFactory keyFactory=KeyFactory.getInstance(KEY_ALGORITHM);
        //初始化公钥
        //密钥材料转换
        X509EncodedKeySpec x509KeySpec=new X509EncodedKeySpec(key);
        //产生公钥
        PublicKey pubKey=keyFactory.generatePublic(x509KeySpec);

        //数据加密
        Cipher cipher=Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        return cipher.doFinal(data);
    }

    /**
     * 私钥解密
     * @param data 待解密数据
     * @param key 密钥
     * @return byte[] 解密数据
     * */
    public static byte[] decryptByPrivateKey(byte[] data,byte[] key) throws Exception{
        //取得私钥
        PKCS8EncodedKeySpec pkcs8KeySpec=new PKCS8EncodedKeySpec(key);
        KeyFactory keyFactory=KeyFactory.getInstance(KEY_ALGORITHM);
        //生成私钥
        PrivateKey privateKey=keyFactory.generatePrivate(pkcs8KeySpec);
        //数据解密
        Cipher cipher=Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }
}

