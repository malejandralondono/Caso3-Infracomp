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
    static HashMap<String,String> tablaPaquetes = new HashMap<>();
    static ArrayList<String> listaUsuarios = new ArrayList<>();

    public static void main(String[] args) throws Exception{
        //Cargar la tabla y la lista de usuarios
        FileReader fr = new FileReader("Caso3/infopaquetes.txt");
        BufferedReader lectorpaquetes = new BufferedReader(fr);
        String info = lectorpaquetes.readLine();
        while (info != null){
            String[] infosep = info.split(",");
            String infousuarios = infosep[0]+","+infosep[1];
            
            listaUsuarios.add(infousuarios);
            tablaPaquetes.put(infousuarios, infosep[2]);
            info = lectorpaquetes.readLine();
        }
        lectorpaquetes.close();
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("Escriba la ruta completa de la ubicación de openssl:");
        //C:\Users\57304\Documents\OpenSSL-1.1.1h_win32\OpenSSL-1.1.1h_win32
        String ruta_openssl = reader.readLine();
        //String ruta_openssl = "C:\\Users\\57304\\Documents\\OpenSSL-1.1.1h_win32\\OpenSSL-1.1.1h_win32";
        while (runtime){
            System.out.println("Bienvenido al menú principal del caso 2. Selecciona una de las siguientes opciones:");
            System.out.println("1. Opción 1");
            System.out.println("2. Opción 2");
            System.out.println("3. Opción 2 pero con el envío del estado del paquete por asimetrico");
            System.out.println("4. Salir");
            
            String resp = reader.readLine();
            if (resp.equals("1")) {
                genASMKeys();
                System.out.println("Funciona!");
            }
            else if (resp.equals("2")){
                
                Tiempo tiempoTOTAL = new Tiempo();
                System.out.println("Indique el número de clientes concurrentes:");
                int cant_clientes = Integer.valueOf(reader.readLine());
                int cantConsultas = 1;
                if (cant_clientes==1) cantConsultas=32;

                
                Servidor servidor = new Servidor(ruta_openssl,tablaPaquetes,cantConsultas);
                servidor.start();
                
                Thread.sleep(50);
                Cliente[] clientes = new Cliente[cant_clientes];
                for (int j=0; j<cant_clientes;j++){
                    clientes[j] = new Cliente(j,listaUsuarios,cantConsultas);   
                    clientes[j].start();
                }
                for (int w=0; w<cant_clientes;w++){
                    clientes[w].join();
                }
                Servidor.setContinuar(false);
                
                System.out.println("Realizar todo el procedimiento tomó "+tiempoTOTAL.getTiempo()+" ms");
            }
            else if (resp.equals("3")){
                Tiempo tiempoTOTALasm = new Tiempo();
                System.out.println("Indique el número de clientes concurrentes:");
                int cant_clientes = Integer.valueOf(reader.readLine());
                int cantConsultas = 1;
                if (cant_clientes==1) cantConsultas=32;

                
                ServidorAsmet servidor = new ServidorAsmet(ruta_openssl,tablaPaquetes,cantConsultas);
                servidor.start();
                
                Thread.sleep(50);
                ClienteAsmet[] clientes = new ClienteAsmet[cant_clientes];
                for (int j=0; j<cant_clientes;j++){
                    clientes[j] = new ClienteAsmet(j,listaUsuarios,cantConsultas);   
                    clientes[j].start();
                }
                for (int w=0; w<cant_clientes;w++){
                    clientes[w].join();
                }
                ServidorAsmet.setContinuar(false);
                
                System.out.println("Realizar todo el procedimiento tomó "+tiempoTOTALasm.getTiempo()+" ms");
            }
            else if (resp.equals("4")){
                runtime = false;
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
