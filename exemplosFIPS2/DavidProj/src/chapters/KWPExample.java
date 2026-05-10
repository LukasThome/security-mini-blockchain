package chapters;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.bouncycastle.util.Arrays;

import static chapters.AEADUtils.createConstantKey;
import java.security.Security;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

/**
 * An example of KWP style key wrapping with padding.
 */
public class KWPExample
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

        // generate an RSA key pair so we have something
        // interesting to work with!
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BCFIPS");

        kpGen.initialize(2048);

        KeyPair kp = kpGen.generateKeyPair();

        // wrap the key
        Cipher wrapCipher = Cipher.getInstance("AESKWP", "BCFIPS");

        wrapCipher.init(Cipher.WRAP_MODE, aesKey);

        byte[] cText = wrapCipher.wrap(kp.getPrivate());

        // unwrap the key
        Cipher unwrapCipher = Cipher.getInstance("AESKWP", "BCFIPS");

        unwrapCipher.init(Cipher.UNWRAP_MODE, aesKey);

        PrivateKey unwrappedKey =
            (PrivateKey)unwrapCipher.unwrap(cText, "RSA", Cipher.PRIVATE_KEY);

        System.out.println("key: " + unwrappedKey.getAlgorithm());
        System.out.println("   : " + Arrays.areEqual(
            kp.getPrivate().getEncoded(), unwrappedKey.getEncoded()));
    }
}
