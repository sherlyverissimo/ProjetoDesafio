package domain;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

import org.json.simple.JSONObject;

public class Criptografia {

	String requestURL =" https://api.codenation.dev/v1/challenge/dev-ps/submit-solution?token=b6fd415e6f1e14644729872e60182c4e87799a9a";

	 
	 public static final String ALGORITHM = "RSA";

	  public static final String PATH_CHAVE_PRIVADA = "C:/keys/private.key";
	
	  public static final String PATH_CHAVE_PUBLICA = "C:/keys/public.key";
	
	  public static void geraChave() {
	    try {
	      final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
	      keyGen.initialize(1024);
	      final KeyPair key = keyGen.generateKeyPair();
	  
	      File chavePrivadaFile = new File(PATH_CHAVE_PRIVADA);
	      File chavePublicaFile = new File(PATH_CHAVE_PUBLICA);
	  
	      // Cria os arquivos para armazenar a chave Privada e a chave Publica
	      if (chavePrivadaFile.getParentFile() != null) {
	        chavePrivadaFile.getParentFile().mkdirs();
	      }
	       
	      chavePrivadaFile.createNewFile();
	  
	      if (chavePublicaFile.getParentFile() != null) {
	        chavePublicaFile.getParentFile().mkdirs();
	      }
	       
	      chavePublicaFile.createNewFile();
	  
	      // Salva a Chave Pública no arquivo
	      ObjectOutputStream chavePublicaOS = new ObjectOutputStream(
	          new FileOutputStream(chavePublicaFile));
	      chavePublicaOS.writeObject(key.getPublic());
	      chavePublicaOS.close();
	  
	      // Salva a Chave Privada no arquivo
	      ObjectOutputStream chavePrivadaOS = new ObjectOutputStream(
	          new FileOutputStream(chavePrivadaFile));
	      chavePrivadaOS.writeObject(key.getPrivate());
	      chavePrivadaOS.close();
	    } catch (Exception e) {
	      e.printStackTrace();
	    }
	  
	  }
	
	  public static boolean verificaSeExisteChavesNoSO() {
	  
	    File chavePrivada = new File(PATH_CHAVE_PRIVADA);
	    File chavePublica = new File(PATH_CHAVE_PUBLICA);
	  
	    if (chavePrivada.exists() && chavePublica.exists()) {
	      return true;
	    }
	     
	    return false;
	  }
	  
	  public static byte[] criptografa(String texto, PublicKey chave) {
	    byte[] cipherText = null;
	     
	    try {
	      final Cipher cipher = Cipher.getInstance(ALGORITHM);
	      // Criptografa o texto puro usando a chave Púlica
	      cipher.init(Cipher.ENCRYPT_MODE, chave);
	      cipherText = cipher.doFinal(texto.getBytes());
	    } catch (Exception e) {
	      e.printStackTrace();
	    }
	     
	    return cipherText;
	  }
	  
	  public static String decriptografa(byte[] texto, PrivateKey chave) {
	    byte[] dectyptedText = null;
	     
	    try {
	      final Cipher cipher = Cipher.getInstance(ALGORITHM);
	    
	      cipher.init(Cipher.DECRYPT_MODE, chave);
	      dectyptedText = cipher.doFinal(texto);
	  
	    } catch (Exception ex) {
	      ex.printStackTrace();
	    }
	  
	    return new String(dectyptedText);
	  }

	  @SuppressWarnings("unchecked")
	public static void main(String[] args) {
	  
	    try {
	  
	      // Verifica se já existe um par de chaves, caso contrário gera-se as chaves..
	      if (!verificaSeExisteChavesNoSO()) {
	       // Método responsável por gerar um par de chaves usando o algoritmo RSA e
	       // armazena as chaves nos seus respectivos arquivos.
	        geraChave();
	      }
	 
	      final String msgOriginal = "b6fd415e6f1e14644729872e60182c4e87799a9a";
	      ObjectInputStream inputStream = null;
	  
	      // Criptografa a Mensagem usando a Chave Pública
	      inputStream = new ObjectInputStream(new FileInputStream(PATH_CHAVE_PUBLICA));
	      final PublicKey chavePublica = (PublicKey) inputStream.readObject();
	      final byte[] textoCriptografado = criptografa(msgOriginal, chavePublica);
	  
	      // Decriptografa a Mensagem usando a Chave Pirvada
	      inputStream = new ObjectInputStream(new FileInputStream(PATH_CHAVE_PRIVADA));
	      final PrivateKey chavePrivada = (PrivateKey) inputStream.readObject();
	      final String textoPuro = decriptografa(textoCriptografado, chavePrivada);
	  
	      JSONObject obj = new JSONObject();
	
		String msgOriginal1 = obj.toJSONString();
		
	      obj.put("",msgOriginal1);
	    	    
	    System.out.printf("\r\n{\n"
	    		+ "numero de casas: 10\n"
	    		+ "token:b6fd415e6f1e14644729872e60182c4e87799a9a\n"
	    		+ "cifrado:" +textoCriptografado.toString().toLowerCase()
	    		+ "\ndecifrado:" +textoPuro.toLowerCase()
	    		+ "\nresumo: resumo criptografado\n"
	    		+ "}");
	 	 
	    
	    } catch (Exception e) {
	      e.printStackTrace();
	    }
	  }
}
