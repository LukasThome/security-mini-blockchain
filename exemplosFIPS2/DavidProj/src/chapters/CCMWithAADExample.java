package chapters;

import javax.crypto.SecretKey;

import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import static chapters.AEADUtils.ccmDecryptWithAAD;
import static chapters.AEADUtils.ccmEncryptWithAAD;
import static chapters.AEADUtils.createConstantKey;
import java.security.Security;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

/**
 * A simple CCM Example with Additional Associated Data (AAD)
 */
public class CCMWithAADExample
{
    public static void main(String[] args)
        throws Exception
    {
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

        System.out.println("msg  : " + Hex.toHexString(msg));
        
        byte[] cText = ccmEncryptWithAAD(aesKey, iv, msg, aad);

        System.out.println("cText: " + Hex.toHexString(cText));

        byte[] pText = ccmDecryptWithAAD(aesKey, iv, cText, aad);

        System.out.println("pText: " + Hex.toHexString(pText));
    }
}
