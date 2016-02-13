package biz.flanagan;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Crypto {

	private static final int BUFFER_SIZE = 8192;

	private final File inputFile;
	private final CipherMode mode;
	private final String password;

	public Crypto(File file, CipherMode mode, String password) {
		this.inputFile = file;
		this.mode = mode;
		this.password = password;
	}

	public File doWork() {

		// TODO better renaming that appends ENCRYPTED/DECRYPTED to the name
		// but before the extension.
		String outputName = this.mode == CipherMode.ENCRYPT ? "ENCRYPTED_" + this.inputFile.getName() : "DECRYPTED_"
				+ this.inputFile.getName().replace("ENCRYPTED_", "");

		File outputFile = new File(inputFile.getParentFile(), outputName);

		OutputStream ous = null;
		InputStream ios = null;
		try {

			byte[] buffer = new byte[BUFFER_SIZE];
			ous = new FileOutputStream(outputFile);
			ios = new FileInputStream(this.inputFile);
			int read = 0;

			CipherPair cipher = CipherPair.createCipher(this.password, this.mode, ios);

			// If we are encrypting, prepend the IV
			if (this.mode == CipherMode.ENCRYPT) {
				ous.write(cipher.getIvBytes(), 0, CipherPair.IV_LENGTH);
			}

			while ((read = ios.read(buffer)) != -1) {
				byte[] toCipher = Arrays.copyOf(buffer, read);
				byte[] fromCipher = cipher.doCryptoWork(toCipher);
				ous.write(fromCipher, 0, fromCipher.length);
			}

			return outputFile;
		} catch (Exception e) {
			throw new RuntimeException(e);
		} finally {
			try {
				if (ous != null)
					ous.close();
			} catch (IOException e) {
			}
			try {
				if (ios != null)
					ios.close();
			} catch (IOException e) {
			}
		}
	}

	protected enum CipherMode {
		ENCRYPT(Cipher.ENCRYPT_MODE), DECRYPT(Cipher.DECRYPT_MODE);

		private final int mode;

		CipherMode(int mode) {
			this.mode = mode;
		}

		public int getMode() {
			return this.mode;
		}
	}

	private static class CipherPair {

		private static final int IV_LENGTH = 16;
		private static final String SALT = "CNSK971837430SJDKF934JDKSJALAJFHDA937718jfkd";

		private final Cipher cipher;

		public static CipherPair createCipher(String key, CipherMode mode, InputStream ios) {

			switch (mode) {
			case ENCRYPT:
				return createEncryptionCipherPair(key);
			case DECRYPT:
				return createDecryptionCipherPair(key, ios);
			default:
				throw new RuntimeException("Bad mode");
			}
		}

		private static CipherPair createEncryptionCipherPair(String key) {
			SecureRandom sr = new SecureRandom();
			byte[] ivBytes = new byte[IV_LENGTH];
			sr.nextBytes(ivBytes);
			IvParameterSpec iv = new IvParameterSpec(ivBytes);

			return new CipherPair(key, CipherMode.ENCRYPT, iv);
		}

		private static CipherPair createDecryptionCipherPair(String key, InputStream is) {
			byte[] ivBytes = new byte[IV_LENGTH];
			try {
				is.read(ivBytes);
				IvParameterSpec iv = new IvParameterSpec(ivBytes);

				return new CipherPair(key, CipherMode.DECRYPT, iv);

			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}

		private CipherPair(String key, CipherMode mode, IvParameterSpec iv) {

			try {
				MessageDigest md = MessageDigest.getInstance("MD5");
				md.update(SALT.getBytes("UTF-8"));
				byte[] keyDigest = md.digest(key.getBytes("UTF-8"));

				SecretKeySpec skeySpec = new SecretKeySpec(keyDigest, "AES");
				this.cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
				this.cipher.init(mode.getMode(), skeySpec, iv);
			} catch (Exception e) {
				throw new RuntimeException(e);
			}
		}

		public byte[] getIvBytes() throws InvalidParameterSpecException {
			IvParameterSpec ivSpec = this.cipher.getParameters().getParameterSpec(IvParameterSpec.class);
			return ivSpec.getIV();
		}

		public byte[] doCryptoWork(byte[] input) throws Exception {
			if (input.length < BUFFER_SIZE) {
				return this.cipher.doFinal(input);
			} else {
				return this.cipher.update(input);
			}
		}
	}

	/*
	 * Three args: [-e/-d] [filename] [password]
	 * 
	 * Example encryption: java -jar EZCrypt.jar -e secrets.txt my_password
	 * Example decryption: java -jar EZCrypt.jar -d secrets_ENC.txt my_password
	 */
	public static void main(String[] args) {
		// Validate args
		validate(args);

		CipherMode mode;
		if (args[0].equals("-e")) {
			mode = CipherMode.ENCRYPT;
		} else {
			mode = CipherMode.DECRYPT;
		}
		new Crypto(new File(args[1]), mode, args[2]).doWork();
	}

	private static void validate(String[] args) {

		if (args.length != 3) {
			printUsage();
		}
		if (!args[0].equals("-e") && !args[0].equals("-d")) {
			printUsage();
		}
		File file = new File(args[1]);
		if (!file.exists()) {
			System.out.println("File not found.");
			printUsage();
		}
	}

	private static void printUsage() {
		System.out
.println("Bad arguments. Usage: \"java -jar EZCrypt.jar [-e/-d] [filename] [password]\"");
		System.out
.println("Example encryption: java -jar EZCrypt.jar -e secrets.txt my_password");
		System.out
.println("Example decryption: java -jar EZCrypt.jar -d secrets_ENC.txt my_password");
		System.exit(1);
	}
}
