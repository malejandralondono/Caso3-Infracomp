import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Cliente extends Thread{


    public static final int PUERTO = 3400;
	public static final String SERVIDOR = "localhost";
    public static Random rnd = new Random();
    public int num;
    private ArrayList<String> listaUsuarios;
    private int cantConsultas;
    public Cliente(int numID, ArrayList<String> listaUsuarios, int cantConsultas){
        this.num = numID;
        this.listaUsuarios = listaUsuarios;
        this.cantConsultas = cantConsultas;
    }
    @Override
    public void run(){
        try {
            Socket socket = null;
            PrintWriter escritor = null;
            BufferedReader lector = null;
            

            System.out.println("Comienza cliente "+num);
            PublicKey llave_pub = getPublicKey();
            //Generar el Reto que dice el enunciado para verificar al servidor
            BigInteger reto = BigInteger.probablePrime(118, rnd);
            Cipher encryptCipher = Cipher.getInstance("RSA");
            encryptCipher.init(Cipher.ENCRYPT_MODE, llave_pub);
            Cipher decryptCipher = Cipher.getInstance("RSA");
            decryptCipher.init(Cipher.DECRYPT_MODE, llave_pub);

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

            //Recibir el paso 8
            String G = lector.readLine();
            String P = lector.readLine();
            String Gx = lector.readLine();
            String firma = lector.readLine();
            //Paso 9 verificar
            byte[] firmaBytes = Base64.getDecoder().decode(firma);
            Signature revisar = Signature.getInstance("SHA1withRSA");
            revisar.initVerify(llave_pub);
            BigInteger Gnum = new BigInteger(G);
            BigInteger Pnum = new BigInteger(P);
            BigInteger Gxnum = new BigInteger(Gx);
            revisar.update(Gnum.toByteArray());
            revisar.update(Pnum.toByteArray());
            revisar.update(Gxnum.toByteArray());

            if (revisar.verify(firmaBytes)){
                //Paso 10
                System.out.println("Firma validada correctamente. Continuando....");
                escritor.println("OK");
            }
            else{
                System.out.println("La firma falló ay");
                escritor.println("ERROR");
            }
            BigInteger y = new BigInteger(Pnum.bitLength() - 1, rnd);
            //AHHHH!
            BigInteger Gy = Gnum.modPow(y, Pnum);
            escritor.println(Gy.toString());
            //Llave simetrica yay
            BigInteger llave = Gxnum.modPow(y, Pnum);
            //System.out.println(llave.toString());
            //escritor.println(llave.toString());

            MessageDigest md = MessageDigest.getInstance("SHA-512"); 
            byte[] digestbien = md.digest(llave.toByteArray());

            byte[] llave_pa_cifrar = Arrays.copyOfRange(digestbien, 0, 32);
            byte[] llave_pa_MAC = Arrays.copyOfRange(digestbien, 32, 64);
            
            SecretKey llaveSimetrica_cifrar = new SecretKeySpec(llave_pa_cifrar, "AES");
            //SecretKey llaveSimetrica_MAC = new SecretKeySpec(llave_pa_MAC, "AES");

            String ivstring = lector.readLine();
            //System.out.println(ivstring);
            byte[] iv = Base64.getDecoder().decode(ivstring);
            IvParameterSpec ivParameterSpec  = new IvParameterSpec(iv);

            
            //Cifrador y descifrador para el envio y recepción de mensajes
            Cipher simetricoCifrado = Cipher.getInstance("AES/CBC/PKCS5Padding");
            simetricoCifrado.init(Cipher.ENCRYPT_MODE, llaveSimetrica_cifrar, ivParameterSpec);
            Cipher simetricoDesCifrado = Cipher.getInstance("AES/CBC/PKCS5Padding");
            simetricoDesCifrado.init(Cipher.DECRYPT_MODE, llaveSimetrica_cifrar, ivParameterSpec);

            //vaino para el hmac
            Mac mac = Mac.getInstance("HmacSHA384");
            SecretKey llavehmac = new SecretKeySpec(llave_pa_MAC, "HmacSHA384");
            mac.init(llavehmac);
            // Print key in hex format
            


            for (int c=0; c<cantConsultas;c++){
                System.out.println("SOLICITUD NUMERO: "+(c+1));
                int num_usuario = rnd.nextInt(listaUsuarios.size()-1);
                String infor_inc = listaUsuarios.get(num_usuario);
                String[] infor = infor_inc.split(",");
                //Paso 13
                byte[] usrbits = infor[0].getBytes("UTF-8");
                byte[] usrCifrado = simetricoCifrado.doFinal(usrbits);
                escritor.println(Base64.getEncoder().encodeToString(usrCifrado));
                byte[] hmacCifrado = mac.doFinal(usrbits);
                escritor.println(Base64.getEncoder().encodeToString(hmacCifrado));
             

                //Paso 14
                byte[] packidBits = infor[1].getBytes("UTF-8");
                byte[] paqCifrado = simetricoCifrado.doFinal(packidBits);
                escritor.println(Base64.getEncoder().encodeToString(paqCifrado));
                byte[] hmacpaqCifrado = mac.doFinal(packidBits);
                escritor.println(Base64.getEncoder().encodeToString(hmacpaqCifrado));
                //Paso 15
                String respuesta = lector.readLine();
                byte[] respuestaBytes = Base64.getDecoder().decode(respuesta);
                byte[] respuestaDesc = simetricoDesCifrado.doFinal(respuestaBytes);
                String respReal =  new String(respuestaDesc, "UTF-8");
                if (!respReal.equals("DESCONOCIDO")){
                    System.out.println("Se preguntó por "+infor[0]+" con el paquete "+infor[1]+" y se recibió que "+respReal);
                }
            }
            escritor.println("TERMINAR");
            
            socket.close();
            escritor.close();
            lector.close();
        }catch (Exception e){
            e.printStackTrace();
        }
		
	}


    public static PublicKey getPublicKey() throws FileNotFoundException {
        FileReader fr = new FileReader("Caso3/llave_publica/llave_pub.txt");
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
