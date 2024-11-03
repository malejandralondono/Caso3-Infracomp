import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;

public class Principal {
    static boolean runtime= true;
    static HashMap<String[],String> tablaPaquetes = new HashMap<>();
    static ArrayList<String[]> listaUsuarios = new ArrayList<>();

    public static void main(String[] args) throws Exception{
        //Cargar la tabla y la lista de usuarios
        FileReader fr = new FileReader("Caso3/infopaquetes.txt");
        BufferedReader lectorpaquetes = new BufferedReader(fr);
        String info = lectorpaquetes.readLine();
        while (info != null){
            String[] infosep = info.split(",");
            String[] infousuarios = {infosep[0],infosep[1]};
            listaUsuarios.add(infousuarios);
            tablaPaquetes.put(infousuarios, infosep[2]);
            info = lectorpaquetes.readLine();
        }
        /*for (String[] a: listaUsuarios){
            System.out.println(a[0] +" "+ a[1] + " " + tablaPaquetes.get(a));
        }*/
        lectorpaquetes.close();
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
                int cantConsultas = 1;
                if (cant_clientes==1) cantConsultas=32;

                for (int i=0; i<cant_serv;i++){
                    Servidor servidor = new Servidor(ruta_openssl,tablaPaquetes,cantConsultas);
                    servidor.start();
                }
                Thread.sleep(50);
                
                for (int j=0; j<cant_clientes;j++){
                    Cliente servidor = new Cliente(j,listaUsuarios,cantConsultas);
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
