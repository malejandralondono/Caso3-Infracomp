import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
public class ServidorAsmet extends Thread {
    
    public static final int PUERTO = 3400;
    String ruta;
    public static boolean continuar=true;
    
    private int cantConsultas;
    private static HashMap<String,String> tablaPaquetes = new HashMap<>();
    
    public static HashMap<String, String> getTablaPaquetes() {
        return tablaPaquetes;
    }


    public ServidorAsmet(String ruta, HashMap<String,String> tablaPaquetes, int cantConsultas) throws Exception{
        this.ruta = ruta;
        setTablaPaquetes(tablaPaquetes);
        this.cantConsultas = cantConsultas;
    }

    
    public static void setTablaPaquetes(HashMap<String, String> tablaPaquetes) {
        ServidorAsmet.tablaPaquetes = tablaPaquetes;
    }


    @Override
    public void run(){   
        try{       
        ServerSocket ss = null;
        ss = new ServerSocket(PUERTO);
        
        System.out.println("servidor iniciado correctamente");
        while (continuar){
            Socket clientSocket = ss.accept();
            System.out.println("Nuevo cliente conectado: " + clientSocket.getInetAddress());
            
            ManejadorCliente clientela = new ManejadorCliente(ruta, cantConsultas, clientSocket);
            clientela.start();
            
        }
        ss.close();
        }catch (Exception e){
            e.printStackTrace();
            System.exit(-1);
        }
    }
    public static void setContinuar(boolean cont) {
        continuar = cont;
    }
    


}

class ManejadorClienteAsimet extends Thread {
    
    String ruta;
    String P;
    String G;

    BigInteger Pnum;
    Socket cliente;
    BigInteger Gnum;
    Cipher descifrador;
    Cipher encifrador;
    Random rand = new Random();
    private int cantConsultas;
    private static HashMap<String,String> tablaPaquetes = Servidor.getTablaPaquetes();
    public ManejadorClienteAsimet(String ruta, int cantConsultas, Socket cliente) throws Exception{
        this.ruta = ruta;
        this.cantConsultas = cantConsultas;
        this.cliente = cliente;
    }

    
    public static void setTablaPaquetes(HashMap<String, String> tablaPaquetes) {
        ManejadorClienteAsimet.tablaPaquetes = tablaPaquetes;
    }


    @Override
    public void run(){   
        try{      
        System.out.println("entramos");
        PrivateKey llave_priv = getPrivateKey();
        
        descifrador = Cipher.getInstance("RSA");
        descifrador.init(Cipher.DECRYPT_MODE, llave_priv);
        encifrador = Cipher.getInstance("RSA");
        encifrador.init(Cipher.ENCRYPT_MODE, llave_priv);
        PrintWriter escritor = new PrintWriter(cliente.getOutputStream(), true);
        BufferedReader lector = new BufferedReader(new InputStreamReader(cliente.getInputStream()));
        //Si recibe algo será guardado en el string recibido con lector.readline
        //String recibido = lector.readLine();
        //Si quiere enviar por la red algo lo hará con escrito.println
        //escritor.println("Hola cliente");
        String retoRecibido = lector.readLine();
        byte [] byteReto = Base64.getDecoder().decode(retoRecibido);

        //Paso 3
        byte[] decryptedMessageBytes = descifrador.doFinal(byteReto);
        String descifradoStr = new String(decryptedMessageBytes, "UTF-8");
        //Paso 4
        escritor.println(descifradoStr);

        //DIFFIE HELMAN
        String Ok1 = lector.readLine();
        if (Ok1.equals("ERROR")){
            System.exit(-1);
        }
        //Paso 7
        //Tiempo tiempo_generador_Diffie = new Tiempo();
        generarP_G();
        
        //Paso 8
        escritor.println(Gnum.toString());
        escritor.println(Pnum.toString());
        SecureRandom rand = new SecureRandom();
        BigInteger x = new BigInteger(Pnum.bitLength() - 1, rand);
        //AHHHH!
        BigInteger Gx = Gnum.modPow(x, Pnum);
        String GxString = Gx.toString();
        escritor.println(GxString);
        //System.out.println("Tiempo que tomó generar G, P y G^x es de "+tiempo_generador_Diffie.getTiempo()+" ms");

        //Crear la firma

        Signature firmita;
        firmita = Signature.getInstance("SHA1withRSA");
        firmita.initSign(llave_priv);
        firmita.update(Gnum.toByteArray());
        firmita.update(Pnum.toByteArray());
        firmita.update(Gx.toByteArray());
        byte[] firmaReal = firmita.sign();
        //Mandar la firma
        escritor.println(Base64.getEncoder().encodeToString(firmaReal));

        String Ok2 = lector.readLine();
        if (Ok2.equals("ERROR")){
            System.exit(-1);
        }

        String Gystring = lector.readLine();
        BigInteger Gynum = new BigInteger(Gystring);
            //Llave simetrica yay
        BigInteger llave = Gynum.modPow(x, Pnum);
        
        //String llaveCliente = lector.readLine();
        //if (llaveCliente.equals(llave.toString())) System.out.println("Funciona diffie yay");

        MessageDigest md = MessageDigest.getInstance("SHA-512"); 
        byte[] digestbien = md.digest(llave.toByteArray());
        byte[] llave_pa_cifrar = Arrays.copyOfRange(digestbien, 0, 32);
        byte[] llave_pa_MAC = Arrays.copyOfRange(digestbien, 32, 64);

        SecretKey llaveSimetrica_cifrar = new SecretKeySpec(llave_pa_cifrar, "AES");
        
        //SecretKey llaveSimetrica_MAC = new SecretKeySpec(llave_pa_MAC, "AES");

        //Generar el inicializador
        byte[] iv = new byte[16];
        rand.nextBytes(iv);
        IvParameterSpec ivParameterSpec  = new IvParameterSpec(iv);

        //Paso 12 enviar el inicializador
        escritor.println(Base64.getEncoder().encodeToString(iv));
        //System.out.println(Base64.getEncoder().encodeToString(iv));
        //cirfador y descifrador
        
        Cipher simetricoCifrado = Cipher.getInstance("AES/CBC/PKCS5Padding");
        simetricoCifrado.init(Cipher.ENCRYPT_MODE, llaveSimetrica_cifrar, ivParameterSpec);
        Cipher simetricoDesCifrado = Cipher.getInstance("AES/CBC/PKCS5Padding");
        simetricoDesCifrado.init(Cipher.DECRYPT_MODE, llaveSimetrica_cifrar, ivParameterSpec);

        //Clase para revisar el hmac
        Mac mac = Mac.getInstance("HmacSHA384");
        SecretKey llavehmac = new SecretKeySpec(llave_pa_MAC, "HmacSHA384");
        mac.init(llavehmac);
        


        for (int c=0; c<cantConsultas;c++){
            boolean todobien = true;
            String usuario = "";
            String paquete = "";
            //Tiempo tiempo_verificar_consulta = new Tiempo();
            String solicitudusuario = lector.readLine();
            
            byte[] temp = Base64.getDecoder().decode(solicitudusuario);
            byte[] usrbits = simetricoDesCifrado.doFinal(temp);
            String hmacusuario = lector.readLine();
            byte[] hmacusuariobyte = mac.doFinal(usrbits);
            String comp1A = new String(hmacusuariobyte, StandardCharsets.UTF_8);
            String comp1B =  new String(Base64.getDecoder().decode(hmacusuario), StandardCharsets.UTF_8);
            if (!comp1A.equals(comp1B)) {
                System.out.println("falla acá en el 1");
                todobien=false;
            }
            else{
                usuario = new String(usrbits, "UTF-8");
                //System.out.println("Primer check de hmac done");
            }
            String solicitudpaquete= lector.readLine();
            
            byte[] packidBits = simetricoDesCifrado.doFinal(Base64.getDecoder().decode(solicitudpaquete));

            String hmacpaquete = lector.readLine();
            byte[] hmacpaqbyte =mac.doFinal(packidBits);
            String comp2A = new String(hmacpaqbyte, StandardCharsets.UTF_8);
            String comp2B =  new String(Base64.getDecoder().decode(hmacpaquete), StandardCharsets.UTF_8);

            if (!comp2A.equals(comp2B)) {
                System.out.println("falla acá en el 2");
                todobien=false;
            }
            else{
                paquete = new String(packidBits, "UTF-8");
                //System.out.println("Segundo check de hmac done");
            }
            //System.out.println("Tiempo que tomó verificar la consulta del cliente es de "+tiempo_verificar_consulta.getTiempoNs()+" ms");
            String acceso = usuario+","+paquete;
            //Si descifró bien todo, debería poder acceder a un dato del HashMap
            String estadoStr = tablaPaquetes.get(acceso);
            if (estadoStr==null) estadoStr="DESCONOCIDO";

            Tiempo tiempo_cifrado_sim = new Tiempo();
            byte[] estadoASM = estadoStr.getBytes("UTF-8");
            //Manda la respuesta cifrada con la simétrica
            byte[] estadocifradoASM = encifrador.doFinal(estadoASM);
            String estadoStrAsm = Base64.getEncoder().encodeToString(estadocifradoASM);
            System.out.println("Tiempo que tomó cifrar asimetricamente el estado del paquete es de "+tiempo_cifrado_sim.getTiempoNs()+" ms");
            byte[] estado = estadoStr.getBytes("UTF-8");
            //Manda la respuesta cifrada con la simétrica
            byte[] estadocifrado = simetricoCifrado.doFinal(estado);
            escritor.println(Base64.getEncoder().encodeToString(estadocifrado));            
            
            if (!todobien) System.out.println("caramba");
        }


        String num = lector.readLine();
        String finalizacion = lector.readLine();
        if (!finalizacion.equals("TERMINAR")) System.out.println("no se finalizó la conexión");
        else System.out.println("Conexión finalizada con el cliente " + num);

        cliente.close();
        escritor.close();
        lector.close();            
        
        }catch (Exception e){
            e.printStackTrace();
            System.exit(-1);
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
        FileReader fr = new FileReader("Caso3/llave_privada/llave_priv.txt");
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
    public void generarP_G ()throws Exception{
        Process process = Runtime.getRuntime().exec(ruta+"\\openssl dhparam -text 1024");
        // Leer la salida del commando
        BufferedReader errreader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String error = errreader.readLine();
        while (error != null) error = errreader.readLine();
	    String line;
	    StringBuilder output = new StringBuilder();
	    // Almacena toda la salida para procesarla después
	     while ((line = reader.readLine()) != null) {
	                output.append(line).append("\n");
	      }
	    reader.close();
        errreader.close();
        process.waitFor();
        String outputText = output.toString();
        Pattern primePattern = Pattern.compile("prime:\\s+([\\s\\S]+?)generator:");
        Pattern generatorPattern = Pattern.compile("generator:\\s+(\\d+)");
        Matcher primeMatcher = primePattern.matcher(outputText);
        if (primeMatcher.find()) {
            this.P = primeMatcher.group(1).replaceAll("\\s+", "");
        }
        Matcher generatorMatcher = generatorPattern.matcher(outputText);
        if (generatorMatcher.find()) {
            this.G = generatorMatcher.group(1);
        }
        String P_Hexa = this.P.replace(":", "").replaceAll("\\s", "");
        this.Pnum = new BigInteger(P_Hexa, 16);
        this.Gnum =new BigInteger(G);

    }

    public static void setContinuar(boolean cont) {
        Servidor.continuar = cont;
    }
    


}
