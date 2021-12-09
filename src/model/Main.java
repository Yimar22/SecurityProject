package model;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Main {

	private static final String SALT = "CHALLENGER";
	private static final String ALGORITHM = "AES/CBC/PKCS5Padding";

	public static void main(String[] args) throws Exception {
		Scanner sc = new Scanner(System.in);
		char[] pass;
		
		System.out.println("Options:");
		System.out.println("[1] Generate new private and public keys (Warning: current keys will be deleted)");
		System.out.println("[2] Sign a file");
		System.out.println("[3] Verify Signature");
		System.out.print("Enter your option: ");
		String opt = sc.nextLine();
		switch (opt) {
		case "1":
			System.out.println("Enter the password to encrypt the private key file");
			pass = sc.nextLine().toCharArray();
			generateKeys(pass);
			System.out.println("New keys generated succesfully");
			break;
		case "2":
			File inputFile = new File("encrypted_id_rsa.cif");
			System.out.print("Enter your password to dencrypt the private key file: ");
			pass = sc.nextLine().toCharArray();
			try {
				byte[] output = decrypt(getKeyFromPassword(pass), inputFile);
				if(output != null) {
					System.out.println("Private Key succesfully decrypted");
					PrivateKey pk = readPrivateKey(output);
					System.out.print("Enter the name of the file to be signed: ");
					String fileToSign = sc.nextLine();
					if(new File(fileToSign).exists()) signFile(fileToSign, pk);
					else System.out.println("File '" + fileToSign + "' doesn't exists!");
				}else {
					System.out.println("Password is incorrect, please try again!");
				}
			} catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException
					| InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException
					| InvalidKeySpecException | IOException e) {
				e.printStackTrace();
			}
			break;
		case "3":
			System.out.println("Enter the name of the file that you want to check");
			String fileToCheck = sc.nextLine();
			if(verifyFile(fileToCheck)) {
				System.out.println("Signature verified");
			}else {
				System.out.println("keys didn't match");
			}
			break;
		default:
			break;
		}
		sc.close();
	}

	private static boolean verifyFile(String fileToCheck) throws NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException, IOException {
		boolean res =false;
			String fileToCheckSig = fileToCheck+".sig";
			PublicKey pk = readPublicKey(new File("id_rsa.pub"));
			Signature sig = Signature.getInstance("SHA1withRSA");
			sig.initVerify(pk);
			
			FileInputStream sigfis = new FileInputStream(fileToCheckSig);
			byte[] sigFile = new byte[sigfis.available()];
			sigfis.read(sigFile);
			sigfis.close();
			
			FileInputStream datafis = new FileInputStream(fileToCheck);
			BufferedInputStream bufin = new BufferedInputStream(datafis);
			byte[] buffer = new byte[1024];
			int len;
			while (bufin.available() != 0) {
			    len = bufin.read(buffer);
			    sig.update(buffer, 0, len);
			};
			bufin.close();
			
		return sig.verify(sigFile);
	}

	private static PublicKey readPublicKey(File file) throws NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] output = null;
		try(FileInputStream fis = new FileInputStream(file)){
		   output=fis.readAllBytes();
		} catch (IOException e){
		    e.printStackTrace();
		}
		
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(output);
		return keyFactory.generatePublic(keySpec);
	}

	private static void signFile(String fileToSign, PrivateKey pk) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException {
		Signature sig = Signature.getInstance("SHA1WithRSA");
		sig.initSign(pk);
		FileInputStream fis = new FileInputStream(fileToSign);
		BufferedInputStream bufin = new BufferedInputStream(fis);
		byte[] buffer = new byte[1024];
		int len;
		while ((len = bufin.read(buffer)) >= 0) {
		    sig.update(buffer, 0, len);
		};
		bufin.close();
		
		byte[] realSig = sig.sign();
		
		FileOutputStream sigfos = new FileOutputStream(fileToSign+".sig");
		sigfos.write(realSig);
		sigfos.close();
	}

	public static PrivateKey readPrivateKey(byte[] input) throws Exception {
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(input);
		return keyFactory.generatePrivate(keySpec);
	}

	private static void generateKeys(char[] pass) {
		KeyPairGenerator keyPairGenerator = null;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {

			e.printStackTrace();
		}
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();
		saveKey(publicKey, "id_rsa.pub");

		saveKey(privateKey, "id_rsa.key");
		File inputFile = new File("id_rsa.key");
		try {
			encryptFile(getKeyFromPassword(pass), inputFile, new File("encrypted_id_rsa.cif"));
			inputFile.delete();
		} catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException
				| InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException
				| InvalidKeySpecException | IOException e) {
			e.printStackTrace();
		}
	}

	private static void saveKey(Key key, String fileName) {
		try (FileOutputStream out = new FileOutputStream(fileName)) {
			out.write(key.getEncoded());
			out.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static SecretKey getKeyFromPassword(char[] password)
			throws NoSuchAlgorithmException, InvalidKeySpecException {

		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		KeySpec spec = new PBEKeySpec(password, SALT.getBytes(), 65536, 128);
		SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
		return secret;
	}

	public static void encryptFile(SecretKey key, File inputFile, File outputFile) throws IOException, NoSuchPaddingException,
	NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
	BadPaddingException, IllegalBlockSizeException {

		Cipher cipher = Cipher.getInstance(ALGORITHM);
		IvParameterSpec iv = generateIv();
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		FileInputStream inputStream = new FileInputStream(inputFile);
		FileOutputStream outputStream = new FileOutputStream(outputFile);
		byte[] hash = hash(inputFile);
		outputStream.write(hash);
		byte[] ivB = iv.getIV();
		outputStream.write(ivB);
		byte[] buffer = new byte[64];
		int bytesRead;
		while ((bytesRead = inputStream.read(buffer)) != -1) {
			byte[] output = cipher.update(buffer, 0, bytesRead);
			if (output != null) {
				outputStream.write(output);
			}
		}
		byte[] outputBytes = cipher.doFinal();
		if (outputBytes != null) {
			outputStream.write(outputBytes);
		}
		inputStream.close();
		outputStream.close();
	}

	public static IvParameterSpec generateIv() {
		byte[] iv = new byte[16];
		new SecureRandom().nextBytes(iv);
		return new IvParameterSpec(iv);
	}

	public static byte[] hash(byte[] input) throws IOException, NoSuchAlgorithmException {
		MessageDigest digest = MessageDigest.getInstance("SHA-1");
		digest.update(input);
		return digest.digest();
	}
	
	public static byte[] hash(File file) throws IOException, NoSuchAlgorithmException {
		MessageDigest digest = MessageDigest.getInstance("SHA-1");
		try(FileInputStream fis = new FileInputStream(file)){
			byte[] buffer = new byte[8192];
			int bytesRead;
			while ((bytesRead = fis.read(buffer)) != -1) {
				if(bytesRead > 0) digest.update(buffer, 0, bytesRead);
			}
			return digest.digest();
		}catch(IOException e) {
			e.printStackTrace();
			return null;
		}
	}

	public static byte[] decrypt(SecretKey key, File inputFile) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {

		Cipher cipher = Cipher.getInstance(ALGORITHM);
		byte[] output = null;
		try (FileInputStream inputStream = new FileInputStream(inputFile)) {
			byte[] hash = new byte[20];
			inputStream.read(hash);
			byte[] ivB = new byte[16];
			inputStream.read(ivB);

			cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivB));

			output = cipher.doFinal(inputStream.readAllBytes());
			byte[] expectedHash = hash(output);
			for (int i = 0; i < expectedHash.length; i++) {
				if(hash[i] != expectedHash[i]) {
					return null;
				}
			}
			return output;
		} catch (IOException | InvalidKeyException | InvalidAlgorithmParameterException e) {
			e.printStackTrace();
			return null;
		}
	}

}
