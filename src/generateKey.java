import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class generateKey {
    public static final String KEY_ALGORITHM="RSA";
    private static final int KEY_SIZE=512;

    public static void main (String[] args) throws Exception {

        //初始化
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KEY_ALGORITHM);
//        设定密匙长度 默认1024
        kpg.initialize(512);
        KeyPair keyPair = kpg.generateKeyPair();
        byte[] publicKey = keyPair.getPublic().getEncoded();
        byte[] privateKey = keyPair.getPrivate().getEncoded();
        //可视化处理
        String publicKeyDisp = Base64.encode(publicKey);
        String privateKeyDisp = Base64.encode(privateKey);

        String text = "123456";

        System.out.println("----------------------------- Public Key -----------------------------");
        System.out.println(publicKeyDisp);
        System.out.println("----------------------------- Private Key -----------------------------");
        System.out.println(privateKeyDisp);
    }
}
