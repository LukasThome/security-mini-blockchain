package chapters;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.jcajce.io.CipherInputStream;
import org.bouncycastle.jcajce.io.CipherOutputStream;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;


/**
 * An example of use of the BC library CipherInputStream/CipherOutputStream
 * classes.
 */
public class CipherIOExample
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
        KeyGenerator kGen = KeyGenerator.getInstance("AES", "BCFIPS");

        SecretKey key = kGen.generateKey();

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BCFIPS");

        byte[] input = Hex.decode("a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7"
                                + "a0a1a2a3a4a5a6a7a0");

        System.out.println("input    : " + Hex.toHexString(input));

        cipher.init(Cipher.ENCRYPT_MODE, key);

        AlgorithmParameters ivParams = cipher.getParameters();

        // encrypt the plain text
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        CipherOutputStream cOut = new CipherOutputStream(bOut, cipher);

        cOut.write(input);
        cOut.close();

        byte[] output = bOut.toByteArray();

        System.out.println("encrypted: " + Hex.toHexString(output));

        cipher.init(Cipher.DECRYPT_MODE, key, ivParams);

        // decrypt the cipher text
        ByteArrayInputStream bIn = new ByteArrayInputStream(output);
        
        CipherInputStream cIn = new CipherInputStream(bIn, cipher);

        byte[] decrypted = Streams.readAll(cIn);

        System.out.println("decrypted: "
                            + Hex.toHexString(decrypted));
    }
}
