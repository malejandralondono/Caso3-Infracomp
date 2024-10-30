import java.io.BufferedReader;
import java.io.InputStreamReader;

public class Principal {
    static boolean runtime= true;
    public static void main(String[] args) throws Exception{
        Servidor servidor = new Servidor();
        while (runtime){
            System.out.println("Bienvenido al menú principal del caso 2. Selecciona una de las siguientes opciones:");
            System.out.println("1. Opción 1");
            System.out.println("2. Opción 2");
            System.out.println("4. Salir");
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String resp = reader.readLine();
            if (resp.equals("1")) {
                servidor.genASMKeys();
                System.out.println("Funciona!");
            }
            else if (resp.equals("2")){
                
            }
        }
    }
}
