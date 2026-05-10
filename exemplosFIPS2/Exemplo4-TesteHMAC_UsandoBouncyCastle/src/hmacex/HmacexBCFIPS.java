package hmacex;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;
import java.util.Scanner;
import javax.crypto.SecretKey;

import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Carla Este exemplo mostra o uso da classe HMac da BouncyCastle.
 * Fevereiro 2021.
 */
public class HmacexBCFIPS {

    public static SecretKey generateKey()
            throws GeneralSecurityException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA512",
                "BCFIPS");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    public static byte[] calculateHmac(SecretKey key, byte[] data)
            throws GeneralSecurityException {
        Mac hmac = Mac.getInstance("HMacSHA512", "BCFIPS");
        hmac.init(key);
        return hmac.doFinal(data);
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        // Instanciar um novo Security provider
        int addProvider = Security.addProvider(new BouncyCastleFipsProvider());

        // Definir chave 
        KeyGenerator keyGenerator
                = KeyGenerator.getInstance("HmacSHA256", "BCFIPS");
        keyGenerator.init(256);
        SecretKey sk = keyGenerator.generateKey();
        //SecretKey sk = new SecretKeySpec(Hex.decode("76b21a33296d9d00d17c9f76372ae53c"),
        //        "HmacSHA256");

        // String para calcular hmac 
        String calcular;
        Scanner input = new Scanner(System.in);
        System.out.println("Digite a msg: ");
        calcular = input.nextLine();
        //calcular = "MAC é um hash com chave";
        
        // Definir e calcular hmac 
        Mac hmac = Mac.getInstance("HMacSHA256", "BCFIPS");
        hmac.init(sk);
        byte[] macValue
                = hmac.doFinal(calcular.getBytes());
        System.out.println("HMAC calculado em array de bytes = "
                + new String(Hex.encode(macValue)));
        System.out.println("HMAC calculado = " + Hex.toHexString(macValue));
        System.out.println("Nome do algoritmo = " + hmac.getAlgorithm());
        System.out.println("Tamanho do MAC = " + hmac.getMacLength());
        
        // Entrada dos dados 
        BufferedReader bufferRead = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("\nDigite Mensagem 1 ");
        byte[] input1 = Utils.toByteArray(bufferRead.readLine());
        System.out.println("Digite Mensagem 2 ");
        byte[] input2 = Utils.toByteArray(bufferRead.readLine());
        byte[] resBuf1 = new byte[hmac.getMacLength()];
        byte[] resBuf2 = new byte[hmac.getMacLength()];
        
        // Hmac da mensagem 1 
        KeyGenerator keyGenerator1 = KeyGenerator.getInstance("HmacSHA512", "BCFIPS");
        keyGenerator1.init(128);
        SecretKey key1;
        key1 = new SecretKeySpec(Hex.decode("d8469f52b8f8688dcebfe4a0b4f7f0d6"), "HmacSHA512");
        
        hmac.init(key1);
        resBuf1 = hmac.doFinal(input1);

        System.out.println("Mensagem 1 = " + Utils.toString(input1));
        System.out.println("Chave 1 = "
                + Hex.toHexString(key1.getEncoded()));
        System.out.println("HMAC da Mensagem 1 = " + new String(Hex.encode(resBuf1)));

        // Hmac da mensagem 2 
        SecretKey key2;
        key2 = new SecretKeySpec(Hex.decode("d8469f52b8f8688dcebfe4a0b4f7f0d6"), "HmacSHA512");
        hmac.reset();
        hmac.init(key2);
        resBuf2 = hmac.doFinal(input2);

        System.out.println("Mensagem 2 = " + Utils.toString(input2));
        System.out.println("Chave 2 = "
                + Hex.toHexString(key2.getEncoded()));
        System.out.println("HMAC da Mensagem 2 = " + new String(Hex.encode(resBuf2)));

        if (!Arrays.equals(resBuf1, resBuf2)) {
            System.out.println("HMACs diferentes");
        } else {
            System.out.println("HMACs iguais");
        }

        // Agora as chaves são diferentes 
        key2 = new SecretKeySpec(Hex.decode("0123456789abcdef"), "HmacSHA512");

        hmac.reset();
        hmac.init(key2);
        resBuf2 = hmac.doFinal(input2);
        if (!Arrays.equals(key1.getEncoded(), key2.getEncoded())) {
            if (!Arrays.equals(resBuf1, resBuf2)) {
                System.out.println(
                        "\n\nCom chaves diferentes, HMACs diferentes");
                System.out.println("Mensagem 1 = " + Utils.toString(input1));
                System.out.println("Chave 1 = " + Hex.toHexString(key1.getEncoded()));
                System.out.println("HMAC da Mensagem 1 = " + new String(Hex.encode(resBuf1)));
                System.out.println("Mensagem 2 = " + Utils.toString(input2));
                System.out.println("Chave 2 = " + Hex.toHexString(key2.getEncoded()));
                System.out.println("HMAC da Mensagem 2 = " + new String(Hex.encode(resBuf2)));
            } else {
                System.out.println("Nunca entra aqui!!");
            }
        }
    
           
                    
    }

}
