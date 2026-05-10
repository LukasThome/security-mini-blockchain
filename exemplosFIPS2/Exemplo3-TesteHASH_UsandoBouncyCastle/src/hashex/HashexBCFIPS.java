package hashex;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.MessageDigest;
import java.util.Scanner;

import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

/**
 *
 * @author Carla Este exemplo mostra o uso da classe Hash da BouncyCastle.
 * Fevereiro 2021.
 */
public class HashexBCFIPS {

    public static byte[] calculateDigest(byte[] data)
            throws GeneralSecurityException {
        MessageDigest hash = MessageDigest.getInstance("SHA512", "BCFIPS");
        System.out.println("Tamanho em bytes SHA512 = " + hash.getDigestLength());
        return hash.digest(data);
    }

    public static byte[] calculateSha3Digest(byte[] data)
            throws GeneralSecurityException {
        MessageDigest hash = MessageDigest.getInstance("SHA3-512", "BCFIPS");
        System.out.println("Tamanho em bytes SHA3-512 = " + hash.getDigestLength());
        return hash.digest(data);
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, GeneralSecurityException {
        // Instanciar um novo Security provider
        int addProvider = Security.addProvider(new BouncyCastleFipsProvider());
                
        // String para calcular hash
        String calcular;
        Scanner input = new Scanner(System.in);
        System.out.println("Digite a mensagem 1: ");
        calcular = input.nextLine();

        byte [] valorHash1 = calculateDigest(calcular.getBytes());

        System.out.println("Hash SHA512 calculado = " + Hex.toHexString(valorHash1));
        
        byte [] valorHash2 = calculateSha3Digest(calcular.getBytes());
        System.out.println("Hash SHA-3 calculado = " + Hex.toHexString(valorHash2));
        
        MessageDigest hash = MessageDigest.getInstance("SHA256", "BCFIPS");
        valorHash2 = hash.digest(calcular.getBytes());
        System.out.println("Tamanho em bytes SHA256 = " + hash.getDigestLength());
        System.out.println("Hash SHA256 calculado = " + Hex.toHexString(valorHash2));
        
        // Calculando SHA256 de outra mensagem
        System.out.println("Digite a mensagem 2: ");
        calcular = input.nextLine();
        valorHash2 = hash.digest(calcular.getBytes());
        System.out.println("Hash SHA256 calculado = " + Hex.toHexString(valorHash2));
        
    }
}
