import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.*;
public class Servidor {
    
    public static final int PUERTO = 3400;

    //public void comenzar() throws IOException{
    public static void main(String[] args) throws IOException {    
        ServerSocket ss = null;
        boolean continuar = true;
        PrivateKey llave_priv = getPrivateKey();
        Cipher decifrador;
     
        try{
            ss = new ServerSocket(PUERTO);
            
        }catch (Exception e){
            e.printStackTrace();
            System.exit(-1);
        }
        System.out.println("iniciado correctamente");
        while (continuar){
            Socket socket = ss.accept();
            try{
                decifrador = Cipher.getInstance("RSA");
                decifrador.init(Cipher.DECRYPT_MODE, llave_priv);
                PrintWriter escritor = new PrintWriter(socket.getOutputStream(), true);
				BufferedReader lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
				//Si recibe algo será guardado en el string recibido con lector.readline
                //String recibido = lector.readLine();
				//Si quiere enviar por la red algo lo hará con escrito.println
				//escritor.println("Hola cliente");
				String retoRecibido = lector.readLine();
                byte [] byteReto = Base64.getDecoder().decode(retoRecibido);

                //Paso 3
                byte[] decryptedMessageBytes = decifrador.doFinal(byteReto);
                String descifradoStr = new String(decryptedMessageBytes, "UTF-8");
                //Paso 4
                escritor.println(descifradoStr);

				socket.close();
				escritor.close();
				lector.close();
            }catch( Exception e){
                e.printStackTrace();
            }
            
        }
        ss.close();
    }

    public void genASMKeys () throws NoSuchAlgorithmException{
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(1024);
        KeyPair keyPair = gen.generateKeyPair();
        PrivateKey privadaKey = keyPair.getPrivate();
        PublicKey publicaKey = keyPair.getPublic();
        String prvkeystr = Base64.getEncoder().encodeToString(privadaKey.getEncoded());
        String pubkeystr = Base64.getEncoder().encodeToString(publicaKey.getEncoded());
        try {
            FileWriter archivoPRIV = new FileWriter("Caso3/llave_privada/llave_priv.txt");
            archivoPRIV.write(prvkeystr);
            archivoPRIV.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        try {
            FileWriter archivoPUB = new FileWriter("Caso3/llave_publica/llave_pub.txt");
            archivoPUB.write(pubkeystr);
            archivoPUB.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public static PublicKey getPublicKey() throws FileNotFoundException {
        FileReader fr = new FileReader("llave_publica/llave_pub.txt");
        BufferedReader br = new BufferedReader(fr);
        PublicKey pubKey = null;
        try {
            String publicK = br.readLine();
            byte[] publicBytes = Base64.getDecoder().decode(publicK);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            pubKey = keyFactory.generatePublic(keySpec);
            br.close();
        } catch (Exception ex) {
        ex.printStackTrace();
        }
        return pubKey;
    }

    public static PrivateKey getPrivateKey() throws FileNotFoundException {
        FileReader fr = new FileReader("llave_privada/llave_priv.txt");
        BufferedReader br = new BufferedReader(fr);
        PrivateKey prvKey = null;
        try {
            String privateK = br.readLine();
            byte[] privateBytes = Base64.getDecoder().decode(privateK);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            prvKey = keyFactory.generatePrivate(keySpec);
            br.close();
        } catch (Exception ex) {
        ex.printStackTrace();
        }
        return prvKey;
    }
    


}
