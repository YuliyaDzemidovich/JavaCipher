package cypher;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import org.apache.log4j.BasicConfigurator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Main {
	private static final String keyfilepath = "key";
	private static final String inputfilepath = "input.jpg";
	private static final String encryptedfilepath = "encrypted";
	private static final String decryptedfilepath = "decrypted";
	
	final Logger log = LoggerFactory.getLogger(Main.class);

	public static void main(String[] args) {
		Main main = new Main();
		// configure log4j
		BasicConfigurator.configure();

		try {
			main.doEncrypt();
			main.doDecrypt();
		} catch (Exception e) {
			main.log.error("Something went wrong");
			e.printStackTrace();
		}
	}

	private void doEncrypt() throws IOException, Exception {
		byte[] plainBytes = Files.readAllBytes(Paths.get(inputfilepath));

		Key encryptionKey = generateKey();
		writeKeyIntoFile(encryptionKey);
		
		byte[] cipherBytes = encrypt(plainBytes, encryptionKey);
		Files.write(Paths.get(encryptedfilepath), cipherBytes, StandardOpenOption.CREATE);

		if (cipherBytes != null) {
			log.debug("data was encrypted successfully");
		}
	}
	
	private void doDecrypt() throws IOException, Exception {
		Key decryptionKey = readKeyFromFile();
		byte[] cipherBytes = Files.readAllBytes(Paths.get(encryptedfilepath));
		byte[] plainBytesDecrypted = decrypt(cipherBytes, decryptionKey);
		if (plainBytesDecrypted != null) {
			log.debug("data was decrypted successfully");
		}
		Files.write(Paths.get(decryptedfilepath), plainBytesDecrypted, StandardOpenOption.CREATE);
	}
	
	private Key generateKey(){
		KeyGenerator keyGen = null;
		try {
			keyGen = KeyGenerator.getInstance("ARCFOUR"); // RC4
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} 
		keyGen.init(1024); // key size from 40 to 1024 bits
		Key key = keyGen.generateKey();
		return key;
	}

	private void writeKeyIntoFile(Key key) {
		 try {
			FileOutputStream fileOut = new FileOutputStream(keyfilepath);
			ObjectOutputStream objectOut = new ObjectOutputStream(fileOut);
			objectOut.writeObject(key);
			objectOut.close();
	        this.log.info("key was successfully written into file");
		} catch (Exception e) {
			this.log.error("key wasn't written into file");
			e.printStackTrace();
		}
        
	}

	private byte[] encrypt(byte[] plainBytes, Key key) throws Exception {
		Cipher cipher = Cipher.getInstance("ARCFOUR"); // RC4
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] cipherBytes = cipher.doFinal(plainBytes);
		return cipherBytes;
	}
	
	private Key readKeyFromFile() {
		Key key = null;
		try {
			FileInputStream fileIn = new FileInputStream(keyfilepath);
			ObjectInputStream objIn = new ObjectInputStream(fileIn);
			key = (Key) objIn.readObject();
			objIn.close();
		} catch (FileNotFoundException e) {
			log.error("key file was not found");
		} catch (IOException e) {
			log.error("key file reading failed");
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			log.error("casting went wrong: from key file to Key object");
			e.printStackTrace();
		}
		if (key == null) {
			log.warn("for some reason key object that was read is still null");
		}
		return key;
	}

	private byte[] decrypt(byte[] cipherBytes, Key key) throws Exception {
		Cipher cipher = Cipher.getInstance("ARCFOUR"); // RC4
		cipher.init(Cipher.DECRYPT_MODE, key, cipher.getParameters());
		byte[] plainBytesDecrypted = cipher.doFinal(cipherBytes);
		return plainBytesDecrypted;
	}
}
