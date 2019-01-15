import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class decode {
    public static void main(String[] args) throws Exception {
        String text = "OZwTSKazmAbBJhd9HMy+No5j0kIPSBCRo1GCrxS5+REhNk1v331jmfuWi9ri3sid45Y74Se+FcorbosxusV/EA==";
        String privateKey="MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEApDo4iZE6E748qCOq6El5CLGFGkAZ9zvqO7kr2R3e0ruoDSralk2lA6rJ/IGSdYw41OuOWaX8aJCb6HLokg0T0QIDAQABAkA9ljvXkyfFeaUDpQSVwd/q26+/rWRPbB+mMAX6kRIb0nweAD2bNnLcUOI1gkEOYrc/cqPezuIdGT5jVa134wLxAiEA0MkGMm8uQkjwzDGth/WkL/fHtXkQPeT5KPMwsRSxpK0CIQDJXajFKEc6HnGieruj6e+Jw1xqGzXKY4Qp3HpMw6FsNQIgck7tRqWadQ4MUC+Oq5Zwixakz5V1r/1x8NqcuQb0b40CIHkFjVVRK93GRk18riGJi6mkfHpY+C83OEtgczCHsxCxAiEAmrJFzVREHacmX60UsuyqcEUGKzJnCG9HD25yDZFcHOM=";

        Cipher cipher = Cipher.getInstance("RSA");//Cipher.getInstance("RSA/ECB/PKCS1Padding");


        String privateKeyString = getKeyString(getPrivateKey(privateKey));
        System.out.println("private:\n" + privateKeyString);

        byte[] keyBytes;
        keyBytes = (new BASE64Decoder()).decodeBuffer(text);


        cipher.init(Cipher.DECRYPT_MODE, getPrivateKey(privateKey));
        byte[]deBytes = cipher.doFinal(keyBytes);
        String decodedDisp = new String(deBytes);
        System.out.println("----------------------------- Decoded -----------------------------");
        System.out.println(decodedDisp);

    }

    public static PrivateKey getPrivateKey(String key) throws Exception {
        byte[] keyBytes;
        keyBytes = (new BASE64Decoder()).decodeBuffer(key);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }

    public static String getKeyString(Key key) throws Exception {
        byte[] keyBytes = key.getEncoded();
        String s = (new BASE64Encoder()).encode(keyBytes);
        return s;
    }
}
