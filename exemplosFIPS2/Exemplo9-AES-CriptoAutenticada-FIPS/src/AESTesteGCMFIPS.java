
/**
 * Código adaptado de várias fontes:
 * https://github.com/bcgit/bc-java/blob/master/prov/src/test/java/org/bouncycastle/jce/provider/test/AESTest.java
 * GCMTest.java da BouncyCastle
 * Modificado para lidar com BouncyCastleFips (https://www.bouncycastle.org/fips-java/BCFipsIn100.pdf)
 * Versão Fevereiro 2021
 */
import java.security.Key;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

import org.bouncycastle.util.Arrays;
import org.apache.commons.codec.binary.Hex;


public class AESTesteGCMFIPS {

    private static final int MAC_SIZE = 128; // in bits
    
    // AES-GCM parameters
    public static final int AES_KEY_SIZE = 128; // in bits
    public static final int GCM_NONCE_LENGTH = 12; // in bytes
    public static final int GCM_TAG_LENGTH = 16; // in bytes

    public AESTesteGCMFIPS() {
    }

    protected boolean areEqual(
            byte[] a,
            byte[] b) {
        return Arrays.areEqual(a, b);
    }

    protected void fail(
            String message
    ) {
        throw new RuntimeException(message);
    }

    // Teste do codigo original do site
    private void gcmTest()
            throws Exception {

        // Test Case 15 from McGrew/Viega
        //  chave (K)
        String pK = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
        byte[] K = org.apache.commons.codec.binary.Hex.decodeHex(pK.toCharArray());

        //  texto plano (P)
        String pP;
        pP = "d9313225f88406e5a55909c5aff5269a"
                + "86a7a9531534f7da2e4c303d8a318a72"
                + "1c3c0c95956809532fcf0e2449a6b525"
                + "b16aedf5aa0de657ba637b391aafd255";
        byte[] P = org.apache.commons.codec.binary.Hex.decodeHex(pP.toCharArray());

        //  nonce (IV)
        String pN;
        pN = "cafebabefacedbaddecaf888";
        byte[] N = org.apache.commons.codec.binary.Hex.decodeHex(pN.toCharArray());

        //  tag (T)
        String T = "b094dac5d93471bdec1a502270e3cc6c";

        //  texto cifrado (C)
        String pC;
        pC = "522dc1f099567d07f47f37a32a84427d"
                + "643a8cdcbfe5c0c97598a2bd2555d1aa"
                + "8cb08e48590dbb3da7b08b1056828838"
                + "c5f61e6393ba7a0abcc9f662898015ad"
                + T;
        byte[] C = org.apache.commons.codec.binary.Hex.decodeHex(pC.toCharArray());

        Key key;
        Cipher in, out;

        in = Cipher.getInstance("AES/GCM/NoPadding", "BCFIPS");
        out = Cipher.getInstance("AES/GCM/NoPadding", "BCFIPS");

        key = new SecretKeySpec(K, "AES");

        in.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(N));

        byte[] enc = in.doFinal(P);

        if (!areEqual(enc, C)) {
            fail("ciphertext doesn't match in GCM");
        }

        out.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(N));

        byte[] dec = out.doFinal(C);

        if (!areEqual(dec, P)) {
            fail("plaintext doesn't match in GCM");
        }

    }

    private void gcmTest2()
            throws Exception {

        // Aproveitando alguns dados do Test Case 15 from McGrew/Viega
        //  chave (K)
        String pK = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
        byte[] K = org.apache.commons.codec.binary.Hex.decodeHex(pK.toCharArray());

        //  texto plano (P)
        byte[] P;

        //  nonce (IV)
        String pN;
        pN = "cafebabefacedbaddecaf888";
        byte[] N = org.apache.commons.codec.binary.Hex.decodeHex(pN.toCharArray());

        //  tag (T)
        String T;
        

        //  texto cifrado (C)
        byte[] C;

        String input = "Transferir 0000100 para CC 1234-5678";
        P = input.getBytes();

        System.out.println("Msg = " + input);

        Key key;
        Cipher in, out;

        in = Cipher.getInstance("AES/GCM/NoPadding", "BCFIPS");
        out = Cipher.getInstance("AES/GCM/NoPadding", "BCFIPS");

        key = new SecretKeySpec(K, "AES");

        GCMParameterSpec​ gcmParameters = new GCMParameterSpec​(MAC_SIZE, N);
        
        //in.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(N));
        in.init(Cipher.ENCRYPT_MODE, key, gcmParameters);

        byte[] enc = in.doFinal(P);
        
        

        System.out.println("Msg cifrada = " + Hex.encodeHexString(enc));        

        out.init(Cipher.DECRYPT_MODE, key, gcmParameters);
        byte[] out2;
        out2 = out.doFinal(enc);

        System.out.println("Msg decifrada = " + Utils.toString(out2));

        // tampering step - mudando o texto cifrado para ver se eh detectado!        
        // A msg cifrada FOI MODIFICADA
        // Deve gerar uma exceção do GCM - GCM Failed
        System.out.println("Ataque -> Tentativa de modificar msg cifrada... ");
        
        enc[11] ^= '0' ^ '9';

        System.out.println("Resultado -> GCM detecta mudanca na tag e causa exception");
        
        out2 = out.doFinal(enc); // aqui acontece a exception

    }

    public static void main(
            String[] args) {
        System.out.println("Teste de GCM com AES usando BCFIPS");

        
        // Incluido: Instanciar um novo Security provider
        int addProvider1 = Security.addProvider(new BouncyCastleFipsProvider());

        if (Security.getProvider("BCFIPS") == null) {
            System.out.println("Bouncy Castle provider NAO disponivel");
        } else {
            System.out.println("Bouncy Castle provider esta disponivel");
        }

        AESTesteGCMFIPS obj = new AESTesteGCMFIPS();
        try {
            // Teste do código original do site (modificado para BCFIPS)
            obj.gcmTest();

            // Teste tentando modificar o texto cifrado para gerar exceção
            obj.gcmTest2();

        } catch (Exception ex) {
            Logger.getLogger(AESTesteGCMFIPS.class.getName()).log(Level.SEVERE, null, ex);
        }

    }
}
