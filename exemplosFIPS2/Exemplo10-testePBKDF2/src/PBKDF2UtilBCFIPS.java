import org.apache.commons.codec.binary.Hex;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Scanner;
import javax.crypto.SecretKey;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

/**
 * User: Carla
 * Date: Fevereiro 2021
 */

public class PBKDF2UtilBCFIPS {

    /**
     * Gerar chave derivada da senha
     * @param key
     * @param salt
     * @param iterations
     * @return
     */
    public static String generateDerivedKey(
            String password, String salt, Integer iterations) {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), 
                salt.getBytes(), iterations, 128);
        SecretKeyFactory pbkdf2 = null;
        String derivedPass = null;
        try {
            pbkdf2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512", "BCFIPS");
            SecretKey sk = pbkdf2.generateSecret(spec);
            derivedPass = Hex.encodeHexString(sk.getEncoded());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return derivedPass;
    }
    
    /*Usado para gerar o salt  */
    public String getSalt() throws NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        //SecureRandom sr = new SecureRandom();
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return Hex.encodeHexString(salt);
    }

    public static void main(String args[]) throws NoSuchAlgorithmException {
        PBKDF2UtilBCFIPS obj = new PBKDF2UtilBCFIPS();     
        
        // Instanciar um novo Security provider
        int addProvider;
        addProvider = Security.addProvider(new BouncyCastleFipsProvider());
        
        String senha = "leopardo";
        String salt = "aafa2148161ec6d4a438fbfa9ded6fdc";
        int it = 1000;
        
        //Scanner input = new Scanner(System.in);
        //System.out.println("Digite a senha: ");
        //senha = input.nextLine();

  
        //salt = obj.getSalt();
        //System.out.println("Digite o salt: ");
        //salt = input.nextLine();
        
        System.out.println("Senha original = " + senha);
        System.out.println("Sal gerado = " + salt);
        System.out.println("Numero de iteracoes = " + it);
        
        String chaveDerivada = generateDerivedKey(senha, salt, it);
       
        System.out.println("Chave derivada da senha = " + chaveDerivada );
        
    }


}
