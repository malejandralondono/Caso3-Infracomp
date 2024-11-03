import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class Principal {
    static boolean runtime= true;
    public static void main(String[] args) throws Exception{
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("Escriba la ruta completa de la ubicación de openssl:");
        //C:\Users\57304\Documents\OpenSSL-1.1.1h_win32\OpenSSL-1.1.1h_win32
        //String ruta_openssl = reader.readLine();
        String ruta_openssl = "C:\\Users\\57304\\Documents\\OpenSSL-1.1.1h_win32\\OpenSSL-1.1.1h_win32";
        while (runtime){
            System.out.println("Bienvenido al menú principal del caso 2. Selecciona una de las siguientes opciones:");
            System.out.println("1. Opción 1");
            System.out.println("2. Opción 2");
            System.out.println("4. Salir");
            
            String resp = reader.readLine();
            if (resp.equals("1")) {
                genASMKeys();
                System.out.println("Funciona!");
            }
            else if (resp.equals("2")){
                
                System.out.println("Indique el número de servidores concurrentes:");
                int cant_serv = Integer.valueOf(reader.readLine());

                System.out.println("Indique el número de clientes concurrentes:");
                int cant_clientes = Integer.valueOf(reader.readLine());
                for (int i=0; i<cant_serv;i++){
                    Servidor servidor = new Servidor(ruta_openssl);
                    servidor.start();
                }
                Thread.sleep(50);
                for (int j=0; j<cant_clientes;j++){
                    Cliente servidor = new Cliente(j);
                    servidor.start();
                }
            }
        }
    }

    public static void genASMKeys () throws NoSuchAlgorithmException{
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
}
