import java.io.IOException;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import javax.crypto.*;
public class Servidor {
    
    public static final int PUERTO = 3400;

    public static void main(String[] args) throws IOException{
        
        ServerSocket ss = null;
        boolean continuar = true;
        try{
            ss = new ServerSocket(PUERTO);
        }catch (IOException e){
            e.printStackTrace();
            System.exit(-1);
        }
        while (continuar){
            Socket socket = ss.accept();

            try{
                PrintWriter escritor = new PrintWriter(socket.getOutputStream());
            }catch( IOException e){
                e.printStackTrace();
            }
            
        }
    }
}
