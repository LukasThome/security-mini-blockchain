
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

/**
 * Symmetric encryption example with padding and CBC using AES with the
 * initialization vector. Modificado para usar o AES.
 */
public class CBCExampleKeyIVSecureRandom {

    public static void main(
            String[] args)
            throws Exception {

        // Array de bytes para cifrar
        byte[] input;

        // Incluido: Instanciar um novo Security provider
        int addProvider = Security.addProvider(new BouncyCastleFipsProvider());

        if (Security.getProvider("BCFIPS") == null) {
            System.out.println("Bouncy Castle provider NAO disponivel");
        } else {
            System.out.println("Bouncy Castle provider esta disponivel");
        }

        // Entrada de dados
        Scanner entrada = new Scanner(System.in);
        System.out.println("Digite a msg para cifrar (texto plano): ");
        String paraCifrar = entrada.nextLine();

        // Transformando string em array de bytes para ser cifrado
        input = paraCifrar.getBytes();

        // Incluido: Gera uma chave AES de 128 bits, provedor BCFIPS
        System.out.print("Gerando chave AES -> ");
        KeyGenerator sKenGen = KeyGenerator.getInstance("AES", "BCFIPS");
        sKenGen.init(128);
        Key aesKey = sKenGen.generateKey();
        System.out.println("Chave = " + Utils.toHex(aesKey.getEncoded()));

        // Incluido: Gerando o iv com SecureRandom   
        System.out.print("Gerando IV -> ");
        byte iv[] = new byte[16];
        //SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        SecureRandom random = SecureRandom.getInstance("DEFAULT", "BCFIPS");
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        System.out.println("IV = " + Utils.toHex(iv));

        // Instanciando cipher
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BCFIPS");

        // passo de cifragem - monta "IV + input"
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);

        byte[] cipherText = new byte[cipher.getOutputSize(iv.length + input.length)];

        int ctLength = cipher.update(iv, 0, iv.length, cipherText, 0);

        ctLength += cipher.update(input, 0, input.length, cipherText, ctLength);

        ctLength += cipher.doFinal(cipherText, ctLength);

        System.out.println("IV + input cifrados : " + Utils.toHex(cipherText, ctLength) + " bytes: " + ctLength);

        // passo decifragem
        cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);

        byte[] buf = new byte[cipher.getOutputSize(ctLength)];

        int bufLength = cipher.update(cipherText, 0, ctLength, buf, 0);

        bufLength += cipher.doFinal(buf, bufLength);

        // remove o IV do início da mensagem
        byte[] plainText = new byte[bufLength - iv.length];

        System.arraycopy(buf, iv.length, plainText, 0, plainText.length);

        System.out.println("Texto plano em bytes : " + Utils.toHex(plainText, plainText.length) + " bytes: " + plainText.length);

        // escreve a string decifrada
        String decifrada = Utils.toString(plainText);
        System.out.println("String decifrada : " + decifrada);
    }
}
