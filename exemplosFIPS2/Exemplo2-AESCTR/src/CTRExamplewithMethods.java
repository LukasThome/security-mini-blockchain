
/**
 *
 * @author Carla
 * @version 3.0 Fevereiro 2021. Usando o BCFIPS.
 */
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

public class CTRExamplewithMethods {

    private Key aesKey;
    private byte[] key;
    private byte iv[];
    private IvParameterSpec ivSpec;
    private Cipher cipher;
    private SecretKeySpec secretKey;

    public void inicia() throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {

        // Instancia o cipher
        //cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BCFIPS");
        cipher = Cipher.getInstance("AES/CTR/NoPadding", "BCFIPS");
        // Gera uma chave AES
        System.out.print("Gerando chave \t-> ");
        KeyGenerator sKenGen;
        sKenGen = KeyGenerator.getInstance("AES", "BCFIPS");
        aesKey = sKenGen.generateKey();
        System.out.println("Chave AES \t= " + Hex.encodeHexString(aesKey.getEncoded()));

        // Chave na String
        //String chave1 = "ec44b993e1de0612e81c4cc1f7433bb5";
        /**
         * try { key = Hex.decodeHex(chave1.toCharArray()); } catch
         * (DecoderException ex) {
         * Logger.getLogger(CTRExamplewithMethods.class.getName()).log(Level.SEVERE,
         * null, ex); }
         
        secretKey = new SecretKeySpec(key, "AES");
        System.out.println("Chave AES \t= " + Hex.encodeHexString(secretKey.getEncoded()));
        */
        // Gerando o iv com SecureRandom
        System.out.print("Gerando IV \t-> ");
        SecureRandom random = SecureRandom.getInstance("DEFAULT", "BCFIPS");
        iv = new byte[16];  
        random.nextBytes(iv); 
        ivSpec = new IvParameterSpec(iv);
        System.out.println("IV \t= " + Hex.encodeHexString(iv));
         
        // IV na String 
        //String iv1 = "f1357039566e00f13d0eeb8bf6975272";
        /**
        try {
            iv = Hex.decodeHex(iv1.toCharArray());
        } catch (DecoderException ex) {
            Logger.getLogger(CTRExamplewithMethods.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        ivSpec = new IvParameterSpec(iv);
        System.out.println("IV \t= " + Hex.encodeHexString(iv));
        */
    } // fim inicia

    public String encrypt(String strToEncrypt) {
        try {
            try {
                inicia();
            } catch (NoSuchProviderException ex) {
                Logger.getLogger(CTRExamplewithMethods.class.getName()).log(Level.SEVERE, null, ex);
            }
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);

            final String encryptedString = Hex.encodeHexString(cipher.doFinal(strToEncrypt.getBytes()));
            return encryptedString;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
        }
        return null;

    }

    public String decrypt(String dec) throws InvalidKeyException, InvalidAlgorithmParameterException {
        try {

            cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);

            byte[] embytes = {};
            try {
                embytes = Hex.decodeHex(dec.toCharArray());
            } catch (DecoderException ex) {
                Logger.getLogger(CTRExamplewithMethods.class.getName()).log(Level.SEVERE, null, ex);
            }

            String decryptedString = new String(cipher.doFinal(embytes));

            return decryptedString;

        } catch (IllegalBlockSizeException | BadPaddingException e) {
            System.out.println(e);
        }
        return null;
    }

    public static void main(String args[]) throws InvalidKeyException, InvalidAlgorithmParameterException {

        // Incluido: Instanciar um novo Security provider
        int addProvider = Security.addProvider(new BouncyCastleFipsProvider());

        if (Security.getProvider("BCFIPS") == null) {
            System.out.println("Bouncy Castle provider NAO disponivel");
        } else {
            System.out.println("Bouncy Castle provider esta disponivel");
        }
        CTRExamplewithMethods obj = new CTRExamplewithMethods();

        String paraCifrar;

        Scanner input = new Scanner(System.in);
        System.out.println("Digite a msg para cifrar: ");
        paraCifrar = input.nextLine();

        System.out.println("Mensagem original = " + paraCifrar);
        String cifrada = obj.encrypt(paraCifrar);
        System.out.println("Mensagem cifrada = " + cifrada);

        String decifrada = obj.decrypt(cifrada);
        System.out.println("Mensagem decifrada = " + decifrada);
    }
}
