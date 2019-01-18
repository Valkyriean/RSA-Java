//import cn.aizichan.utils.digest.RSACoder;
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

import java.util.Map;

public class RSATester {
    public static void main(String[] args) throws Exception {
        RSACoder rsa = new RSACoder();
        String text = "987654321";

        System.out.println("The text is         " + text);
        System.out.println("The public key is   " + rsa.getPublicKeyS());
        System.out.println("The private key is  " + rsa.getPrivateKeyS());
        String encoded = rsa.encryptByPublicKey(text);
        System.out.println("The encoded text is "+encoded);
        String decoded = rsa.decryptByPrivateKey(encoded);
        System.out.println("The decoded text is "+decoded);
    }

}
