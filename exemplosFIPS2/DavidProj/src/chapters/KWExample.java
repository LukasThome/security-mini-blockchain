package chapters;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import static chapters.AEADUtils.createConstantKey;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;
import javax.crypto.KeyGenerator;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

/**
 * An example of KW style key wrapping - note in this case the input must be
 * aligned on an 8 byte boundary (for AES).
 * Modificado Julho 2021.
 */
public class KWExample {

    public static void main(String[] args)
            throws Exception {
        // Incluido: Instanciar um novo Security provider
        int addProvider = Security.addProvider(new BouncyCastleFipsProvider());

        if (Security.getProvider("BCFIPS") == null) {
            System.out.println("Bouncy Castle provider NAO disponivel");
        } else {
            System.out.println("Bouncy Castle provider esta disponivel");
        }

        // Incluido: Gera uma chave AES de 128 bits, provedor BCFIPS
        System.out.print("Gerando chave AES -> ");
        KeyGenerator sKenGen = KeyGenerator.getInstance("AES", "BCFIPS");
        sKenGen.init(128);
        SecretKey aesKey = sKenGen.generateKey();
        System.out.println("Chave = " + Hex.toHexString(aesKey.getEncoded()));

        // Chave com valor fixo no código - não usar assim!
        //SecretKey aesKey = createConstantKey();
        
        // Chave com valor fixo no código - não usar assim!
        //SecretKeySpec keyToWrap = new SecretKeySpec(Hex.decode("00010203040506070706050403020100"), "Blowfish");
        
        // Gera uma chave Blowfish
        System.out.print("Gerando chave Blowfish \t-> ");
        SecureRandom random = SecureRandom.getInstance("DEFAULT", "BCFIPS");
        byte sorteio[] = new byte[8];
        random.nextBytes(sorteio);

        SecretKeySpec keyToWrap = new SecretKeySpec(sorteio, "Blowfish");
        System.out.println("Chave Blowfish \t= " + Hex.toHexString(keyToWrap.getEncoded()));

        // wrap the key
        Cipher wrapCipher = Cipher.getInstance("AESKW", "BCFIPS");

        wrapCipher.init(Cipher.WRAP_MODE, aesKey);

        byte[] cText = wrapCipher.wrap(keyToWrap);

        // unwrap the key
        Cipher unwrapCipher = Cipher.getInstance("AESKW", "BCFIPS");

        unwrapCipher.init(Cipher.UNWRAP_MODE, aesKey);

        SecretKey unwrappedKey
                = (SecretKey) unwrapCipher.unwrap(cText, "Blowfish", Cipher.SECRET_KEY);

        System.out.println("key: " + unwrappedKey.getAlgorithm());
        System.out.println("   : " + Arrays.areEqual(
                keyToWrap.getEncoded(),
                unwrappedKey.getEncoded()));
        
        
        
        // Novo teste
        
        
        // Incluido: Gera uma chave AES de 128 bits, provedor BCFIPS
        System.out.print("Gerando chave AES para ser wrapped -> ");
        byte sorteio16bytes[] = new byte[16];
        random.nextBytes(sorteio16bytes);
        keyToWrap = new SecretKeySpec(sorteio16bytes, "AES");
        
        System.out.println("Chave = " + Hex.toHexString(aesKey.getEncoded()));
        
        // wrap the key
        wrapCipher = Cipher.getInstance("AESKW", "BCFIPS");

        wrapCipher.init(Cipher.WRAP_MODE, aesKey);

        cText = wrapCipher.wrap(keyToWrap);

        // unwrap the key
       unwrapCipher = Cipher.getInstance("AESKW", "BCFIPS");

        unwrapCipher.init(Cipher.UNWRAP_MODE, aesKey);

        unwrappedKey
                = (SecretKey) unwrapCipher.unwrap(cText, "AES", Cipher.SECRET_KEY);

        System.out.println("key: " + unwrappedKey.getAlgorithm());
        System.out.println("   : " + Arrays.areEqual(
                keyToWrap.getEncoded(),
                unwrappedKey.getEncoded()));
    }
}
