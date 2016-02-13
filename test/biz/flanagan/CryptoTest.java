package biz.flanagan;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Random;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import biz.flanagan.Crypto.CipherMode;

public class CryptoTest {

	@Rule
	public TemporaryFolder folder = new TemporaryFolder();

	@Test
	public void encryptionDecryptionRoundtrip() throws IOException {

		byte[] clearBytes = new byte[100000];
		Random random = new Random();
		random.nextBytes(clearBytes);

		String password = "password";

		// Create clear text file
		File clearTextFile = folder.newFile("clearText.txt");
		Files.write(clearTextFile.toPath(), clearBytes);

		// Create Crypto and encrypt
		Crypto crypto = new Crypto(clearTextFile, CipherMode.ENCRYPT, password);
		File encryptedFile = crypto.doWork();

		// Create Crypto for decryption
		Crypto decrypto = new Crypto(encryptedFile, CipherMode.DECRYPT, password);
		File decryptedFile = decrypto.doWork();

		byte[] decryptedClearText = Files.readAllBytes(decryptedFile.toPath());

		assertTrue(Arrays.equals(clearBytes, decryptedClearText));
	}
}
