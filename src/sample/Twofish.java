package sample;

import javafx.concurrent.Task;
import javafx.scene.control.ProgressBar;
import org.xml.sax.SAXException;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

/**
 * Created by Michuuuu on 2017-04-18.
 */
public class Twofish {

    public Twofish(){}


    static public void encrypt(File ifFile, List<User> users, String outFileName, String cipherMode, String keyLength, String subBlock, ProgressBar pb) throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidKeyException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException, InvalidKeySpecException, ShortBufferException, TransformerException, ParserConfigurationException {

        //klucz do szyfrowania wiadomosc
        SecretKey symetricKey = generateSymetricKey(Integer.parseInt(keyLength));


        Cipher cipher;
        if(cipherMode.equals("OFB")||cipherMode.equals("CFB"))
            cipher = Cipher.getInstance("Twofish/"+cipherMode+subBlock+"/PKCS5Padding", "IAIK");
        else
            cipher = Cipher.getInstance("Twofish/"+cipherMode+"/PKCS5Padding", "IAIK");




        cipher.init(Cipher.ENCRYPT_MODE, symetricKey);


        byte[] ivBytes = cipher.getIV();
        FileInputStream fis = new FileInputStream(ifFile.toString());

        File f = new File("encryptedFiles");
        if (f.exists()) {
            System.out.println("nie tworze encryptedFiles");
        } else
            new File("encryptedFiles").mkdir();


        //zaszyfrowany klucz sesyjny kluczem publicznym odbiorcy
        Map<String,byte[]> sessionKeyList = new HashMap<String, byte[]>();
        for(User u : users){
            PublicKey pubkey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(u.publicKey));
            byte[] encryptedSessionKey = rsaKeyEncryption(symetricKey.getEncoded(),pubkey);
            sessionKeyList.put(u.name,encryptedSessionKey);
        }


        File file = new File("encryptedFiles\\" + outFileName + ".enc");
        if(!subBlock.equals("2")){
            XMLparser.XMLcreateHeader("encryptedFiles\\" + outFileName + ".enc",users,keyLength,"128",cipherMode,ivBytes,sessionKeyList,subBlock);
            XMLparser.XMLcreateHeaderNeat(outFileName + ".enc",users,keyLength,"128",cipherMode,ivBytes,sessionKeyList,subBlock);

        }

        Task t = new Task() {
            @Override
            protected Object call() throws Exception {
                FileOutputStream fos = new FileOutputStream(file.getAbsolutePath(),true);
                //doxml
                FileOutputStream fos2 = new FileOutputStream("data\\encryptedFiles\\"+outFileName+".enc",true);


                double progress = 0;
                double maxProgress = ifFile.length();
                updateProgress(0, maxProgress);
                RandomAccessFile fi = new RandomAccessFile(ifFile, "r");
                byte[] input = new byte[1024];
                int byteCount;
                while((byteCount = fi.read(input)) != -1){

                    byte[] encrypted = cipher.update(input, 0, byteCount);

                    progress += byteCount;
                    updateProgress(progress, maxProgress);

                    fos.write(encrypted);
                    fos2.write(encrypted);
                }
                byte [] done = cipher.doFinal();
                fos.write(done);
                fos2.write(done);
                fos.close();
                fos2.close();

                Thread.sleep(1500);
                updateProgress(0, 1);

                return null;
            }
        };
        pb.progressProperty().bind(t.progressProperty());
        new Thread(t).start();



        fis.close();

    }


    //to encrypt privateKey using hash from user's password
    static public byte[] encrypt(byte[] hashedKey, PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidKeyException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException {

        Cipher cipher = Cipher.getInstance("Twofish/ECB/PKCS5Padding", "IAIK");
        SecretKeySpec secretKeySpec = new SecretKeySpec(hashedKey,"TWOFISH");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        byte[] outPut = cipher.doFinal(privateKey.getEncoded());
        return outPut;
    }

    static public byte[] decrypt(byte[] privateKey, byte[] hashedPW) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        SecretKeySpec secretKeySpec = new SecretKeySpec(hashedPW,"TWOFISH");
        Cipher cipher = Cipher.getInstance("Twofish/ECB/PKCS5Padding", "IAIK");
        cipher.init(Cipher.DECRYPT_MODE,secretKeySpec);
        byte[] outPut = cipher.doFinal(privateKey);
        return  outPut;
    }


    static public void decrypt(File ifFile, String password, User u,String outFileName,ProgressBar progressBar) throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidKeyException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException, InvalidKeySpecException, ShortBufferException, ParserConfigurationException, SAXException {

        byte[] hashPW = getHashFromPW(password);
        byte[] privateKey = decrypt(u.privateKey,hashPW);


        String cipMode = XMLparser.XMLgetElement(ifFile,"CipherMode");
        String subBlockSize = XMLparser.XMLgetElement(ifFile,"SegmentSize");
        byte[] sess = XMLparser.XMLgetSessionKey(ifFile,u);

        PrivateKey privateKey1 = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKey));

        byte[] sessionKey = rsaKeyDecryption(sess,privateKey1);

        // create a SecretKeySpec from key material
        SecretKeySpec secretKeySpec = new SecretKeySpec(sessionKey, "Twofish");

        IvParameterSpec iv;
        Cipher cipher;
        if(cipMode.equals("OFB")|| cipMode.equals("CFB"))
            cipher = Cipher.getInstance("Twofish/"+cipMode+subBlockSize+"/PKCS5Padding", "IAIK");
        else
            cipher = Cipher.getInstance("Twofish/"+cipMode+"/PKCS5Padding", "IAIK");


        if(!cipMode.equals("ECB")){
            iv = new IvParameterSpec(Base64.getDecoder().decode(XMLparser.XMLgetElement(ifFile,"IV")));
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec,iv);
        }else
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

        // get Cipher and init it for encryption


        //to-do tworzenie foldera
        FileInputStream fis = new FileInputStream(ifFile.toString());
        File file = new File("decryptedFiles\\" + outFileName);
        file.createNewFile();



        Task task = new Task() {
            @Override
            protected Object call() throws Exception {
                FileOutputStream fos = new FileOutputStream(file.getAbsolutePath());
                CipherInputStream cis = new CipherInputStream(fis, cipher);





                int toskip = XMLparser.XMLhowManyToSkip(ifFile) + 1;
                int len = 1024;
                byte[] input = new byte[len];
                int byteCount;
                FileInputStream fiii = new FileInputStream(ifFile);
                fiii.skip(toskip);
                double progress = 0;
                double maxProgress = ifFile.length() - toskip;
                updateProgress(0, maxProgress);
                CipherInputStream cis2 = new CipherInputStream(fiii, cipher);
                while ((byteCount = cis2.read(input)) != -1 ){
                    progress += byteCount;
                    updateProgress(progress,maxProgress);
                    fos.write(input,0,byteCount);
                }

                fos.close();
                updateProgress(1, 1);
                Thread.sleep(1500);
                updateProgress(0, 1);
                return null;
            }
        };
        progressBar.progressProperty().bind(task.progressProperty());
        new Thread(task).start();


        fis.close();


    }

    static public void decryptWithBadPW(File ifFile, String password, User u,String outFileName,ProgressBar progressBar) throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidKeyException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException, InvalidKeySpecException, ShortBufferException, ParserConfigurationException, SAXException {

        Cipher cipher;
        cipher = Cipher.getInstance("Twofish/"+"ECB"+"/PKCS5Padding", "IAIK");

        byte[] key = (password).getBytes("UTF-8");
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        key = sha.digest(key);
        key = Arrays.copyOf(key, 16);

        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);


        byte[] ivBytes = cipher.getIV();
        FileInputStream fis = new FileInputStream(ifFile.toString());

        File f = new File("encryptedFiles");
        if (f.exists()) {
            System.out.println("nie tworze encryptedFiles");
        } else
            new File("encryptedFiles").mkdir();




        File file = new File("decryptedFiles\\" + outFileName);


        Task t = new Task() {
            @Override
            protected Object call() throws Exception {
                FileOutputStream fos = new FileOutputStream(file.getAbsolutePath(),true);
                //doxml
                //FileOutputStream fos2 = new FileOutputStream("data\\encryptedFiles\\"+outFileName+".enc",true);


                double progress = 0;
                double maxProgress = ifFile.length();
                updateProgress(0, maxProgress);
                RandomAccessFile fi = new RandomAccessFile(ifFile, "r");
                byte[] input = new byte[1024];
                int byteCount;
                while((byteCount = fi.read(input)) != -1){

                    byte[] encrypted = cipher.update(input, 0, byteCount);

                    progress += byteCount;
                    updateProgress(progress, maxProgress);

                    fos.write(encrypted);
                }
                byte [] done = cipher.doFinal();
                fos.write(done);
                fos.close();

                Thread.sleep(1500);
                updateProgress(0, 1);

                return null;
            }
        };
        progressBar.progressProperty().bind(t.progressProperty());
        new Thread(t).start();
        fis.close();

    }


    static  public byte[] rsaKeyEncryption(byte[] sessionKey, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "IAIK");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] bytes = sessionKey;
        byte[] outPut = cipher.doFinal(bytes);

        return  outPut;


    }

    static  public byte[] rsaKeyDecryption(byte[] sessionKey, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "IAIK");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);


        byte[] bytes = sessionKey;
        byte[] outPut = cipher.doFinal(bytes);

        return  outPut;


    }
    static public KeyPair getRSAkeys() throws NoSuchAlgorithmException, NoSuchProviderException {

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "IAIK");
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG", "SUN");
        generator.initialize(512, sr);
        KeyPair keyPair = generator.generateKeyPair();

        return keyPair;

    }

    static public byte[] getHashFromPW(String s) throws NoSuchAlgorithmException, UnsupportedEncodingException {

        MessageDigest md = MessageDigest.getInstance("SHA-256");

        md.update(s.getBytes("UTF-8")); // Change this to "UTF-16" if needed
        byte[] hashedKey = md.digest();

        //java  wspiera tylko 128 bitowe klucze/ dla dluzszych trzeba doinstalowac jce ultimate strength bierzemy pierwsze 16 bajtow
        hashedKey = Arrays.copyOf(hashedKey, 16);

        return hashedKey;
    }
    static public SecretKey generateSymetricKey(int keyLength) throws NoSuchProviderException, NoSuchAlgorithmException {

        KeyGenerator keyGenerator = KeyGenerator.getInstance("TWOFISH");
        //keyGenerator.init(keyLength);
        SecureRandom sr = new SecureRandom();
        keyGenerator.init(128,sr);
        SecretKey secretKey = keyGenerator.generateKey();
        return  secretKey;
    }
}
