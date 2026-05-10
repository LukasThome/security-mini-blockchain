package chapters;

import java.security.Security;

import javax.crypto.SecretKey;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import static chapters.AEADUtils.createConstantKey;
import static chapters.AEADUtils.gcmDecryptWithAAD;
import static chapters.AEADUtils.gcmEncryptWithAAD;
import java.util.Arrays;

/**
 * A simple GCM example with Additional Associated Data (AAD)
 */
public class GCMWithAADExample {

    public static void main(String[] args)
            throws Exception {
        // Incluido: Instanciar um novo Security provider
        int addProvider = Security.addProvider(new BouncyCastleFipsProvider());

        if (Security.getProvider("BCFIPS") == null) {
            System.out.println("Bouncy Castle provider NAO disponivel");
        } else {
            System.out.println("Bouncy Castle provider esta disponivel");
        }
        SecretKey aesKey = createConstantKey();

        byte[] iv = Hex.decode("bbaa99887766554433221100");
        byte[] msg = Strings.toByteArray("hello, world!");
        byte[] aad = Strings.toByteArray("now is the time!");
        
        System.out.println("msg in plaintext  : " + new String(msg, "UTF-8"));
        System.out.println("aad in plaintext  : " + new String(aad, "UTF-8"));
        
        System.out.println("msg  : " + Hex.toHexString(msg));

        byte[] cText = gcmEncryptWithAAD(aesKey, iv, msg, aad);

        System.out.println("cText: " + Hex.toHexString(cText));

        byte[] pText = gcmDecryptWithAAD(aesKey, iv, cText, aad);

        System.out.println("pText: " + Hex.toHexString(pText));
        System.out.println("msg in plaintext  : " + new String(pText, "UTF-8"));
    }
}
