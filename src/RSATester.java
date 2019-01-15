//import cn.aizichan.utils.digest.RSACoder;
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

import java.util.Map;

public class RSATester {
    public static void main(String[] args) throws Exception {
        //初始化密钥
        //生成密钥对
        Map<String,Object> keyMap= RSACoder.initKey();
        //公钥
        byte[] publicKey=RSACoder.getPublicKey(keyMap);
        //byte[] publicKey = b;
        //私钥
        byte[] privateKey=RSACoder.getPrivateKey(keyMap);
        System.out.println("公钥："+Base64.encode(publicKey));
        System.out.println("私钥："+Base64.encode(privateKey));

        System.out.println("================密钥对构造完毕,甲方将公钥公布给乙方，开始进行加密数据的传输=============");
        String str="aattaggcctegthththfef/aat.mp4";
        System.out.println("===========甲方向乙方发送加密数据==============");
        System.out.println("原文:"+str);
        //甲方进行数据的加密
        byte[] code1=RSACoder.encryptByPublicKey(str.getBytes(), publicKey);
        System.out.println("甲方 使用乙方公钥加密后的数据："+ Base64.encode(code1));
        System.out.println("===========乙方使用甲方提供的公钥对数据进行解密==============");
        //乙方进行数据的解密
        //byte[] decode1=RSACoderReal.decryptByPublicKey(code1, publicKey);
        byte[] decode1=RSACoder.decryptByPrivateKey(code1, privateKey);
        System.out.println("乙方解密后的数据："+new String(decode1)+"");
    }

}
