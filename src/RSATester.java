//import cn.aizichan.utils.digest.RSACoder;
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

import java.util.Map;

public class RSATester {
    public static void main(String[] args) throws Exception {
        RSACoder rsa = new RSACoder();
        String text = "12345678";

        System.out.println("The text is         " + text);
        System.out.println("The public key is   " + rsa.getPublicKey());
        System.out.println("The private key is  " + rsa.getPrivateKey());
        String encoded = rsa.encryptByPublicKey(text);
        String decoded = rsa.decryptByPrivateKey(encoded);
        System.out.println("The encoded text is "+encoded);
        System.out.println("The decoded text is "+decoded);
    }

}
