import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Random;

import javax.crypto.Cipher;

public class Cliente extends Thread{


    public static final int PUERTO = 3400;
	public static final String SERVIDOR = "localhost";
    public static Random rnd = new Random();
    /*@Override
    public void run(){*/
    public static void main(String[] args) throws IOException {
        try {
            Socket socket = null;
            PrintWriter escritor = null;
            BufferedReader lector = null;
            

            System.out.println("Comienza cliente");
            PublicKey llave_pub = getPublicKey();
            //Generar el Reto que dice el enunciado para verificar al servidor
            BigInteger reto = BigInteger.probablePrime(118, rnd);
            Cipher encryptCipher = Cipher.getInstance("RSA");
            encryptCipher.init(Cipher.ENCRYPT_MODE, llave_pub);

            String retoStr = reto.toString();
            System.out.println("String que debería aparecer: "+retoStr);
            byte[] retoPLAINTEXTbits = retoStr.getBytes("UTF-8");
            //Paso 2a
            byte[] retoCifrado = encryptCipher.doFinal(retoPLAINTEXTbits);

            //Comunicación con el servidor
            socket = new Socket(SERVIDOR, PUERTO);
            escritor = new PrintWriter(socket.getOutputStream(), true);
            lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        
            //Paso 2b
            escritor.println(Base64.getEncoder().encodeToString(retoCifrado));
            
            //Paso 5
            String rta = lector.readLine();
          

            System.out.println("retostr: "+retoStr);
            System.out.println("rta: "+rta);

            //Paso 6
            if (retoStr.equals(rta)) {
                System.out.println("Servidor validado correctamente. Continuando....");
                escritor.println("OK");
            }
            else {
                System.out.println("Este no es el servidor correcto HUYAN");
                escritor.println("ERROR");
                System.exit(-1);
            }
            
            socket.close();
            escritor.close();
            lector.close();
        }catch (Exception e){
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

    
        
    
    
}
