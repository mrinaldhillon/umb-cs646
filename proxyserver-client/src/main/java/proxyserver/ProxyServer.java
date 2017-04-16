import java.net.*;
import java.io.*;

public class ProxyServer {
  public static void main(String[] args) throws IOException {

    if (args.length != 1) {
      System.err.println("Usage: java EchoServer <port number>");
      System.exit(1);
    }

    int portNumber = Integer.parseInt(args[0]);

    try{
      ServerSocket serverSocket =
        new ServerSocket(portNumber);

      while(true){
        Socket clientSocket = serverSocket.accept();     
        ClientWorker w=new ClientWorker(clientSocket);
        Thread t=new Thread(w);
        t.start();
      }

    } catch (IOException e) {
      System.out.println("Exception caught when trying to listen on port "
          + portNumber + " or listening for a connection");
      System.out.println(e.getMessage());
    }
  }
}

class ClientWorker implements Runnable {
  private Socket client;

  //Constructor
  ClientWorker(Socket client) {
    this.client = client;
  }

  public void httpGetContent(String targetUrl, PrintWriter out) {
    int contentLength = -1;
    int port = -1;
    Socket s = null;
    URL url= null;
    PrintWriter pw = null;
    BufferedReader br = null;
    System.out.println("[debug:] URL: " + targetUrl);
    try {
      if (targetUrl.startsWith("http://")) {
        url = new URL(targetUrl);
        port = 80;
      } else if (targetUrl.startsWith("https://")) {
        url = new URL(targetUrl);
        port = 443;
      } else {
        url = new URL("http://" + targetUrl);
        port = 80;
      }
      
      String hostPath = url.getHost().toString();
      String subPath = url.getPath().toString();
      s = new Socket(InetAddress.getByName(hostPath), port);
      pw = new PrintWriter(s.getOutputStream());
      pw.print("GET " + subPath + " HTTP/1.1\r\n");
      pw.print("Host: " + hostPath + "\r\n");
      pw.print("User-Agent: proxyserver-cs646\r\n");
      pw.print("Accept: */*\r\n");
      pw.print("Connection: close\r\n\r\n");
      pw.flush();
      br = new BufferedReader(new InputStreamReader (s.getInputStream()));
      String t;
    
      //read header
      while((t = br.readLine()) != null) {
        if(t.startsWith("Content-Length:")) {
          String cl = t.replaceFirst("Content-Length: ", "");
          contentLength = Integer.parseInt(cl);
          out.println(contentLength);
          System.out.println("[debug]: Content Length:" + contentLength);
        }
        if (t.isEmpty()) {
          break;
        }
      }
      //read&write data
      for (int i = 0; i < contentLength; i++) {
        out.write(br.read());
      }

      br.close();
      s.close();
    } catch (Exception e) {
      System.out.println("Exception:" + e.getMessage());
    }
  }

  public void run() {
    String line, verb, url;
    BufferedReader in = null;
    PrintWriter out = null;
    try{
      in = new BufferedReader(new InputStreamReader(client.getInputStream()));
      out = new PrintWriter(client.getOutputStream(), true);
    } catch (IOException e) {
      System.out.println("in or out failed");
      System.exit(-1);
    }
    while(true){
      try{
        line = in.readLine();
        if (line.isEmpty()){
          client.close();
          break;
        }
        String[] tokens = line.split(" ");
        if (tokens[0].equals("GET")) {
          httpGetContent(tokens[1], out);
          out.flush();
        }
      }catch (IOException e) {
        e.printStackTrace();
        System.out.println("EMessage:" + e.getMessage());
        System.out.println("Read failed");
        System.exit(-1);
      }
    }
  }
}
