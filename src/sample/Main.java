package sample;

import iaik.security.provider.IAIK;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

import javax.crypto.*;
import javax.crypto.CipherSpi.*;
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.*;
import javax.crypto.spec.*;
import javax.jws.soap.SOAPBinding;

//import org.bouncycastle.util.encoders.Hex;
public class Main extends Application {

    @Override
    public void start(Stage primaryStage) throws Exception {
        Parent root = FXMLLoader.load(getClass().getResource("sample.fxml"));
        primaryStage.setTitle("Michal Treder 151705 TwoFish + RSA");
        primaryStage.setScene(new Scene(root, 590, 575));
        primaryStage.show();
    }


    public static void main(String[] args) {

        IAIK.addAsProvider();

//        try {
//            Field field = Class.forName("javax.crypto.JceSecurity").getDeclaredField("isRestricted");
//            field.setAccessible(true);
//            field.set(null, java.lang.Boolean.FALSE);
//        } catch (Exception ex) {
//            System.out.println("Nie mozna zmienic polityki kluczy");
//        }


        System.out.println("siema");

        String toEncrypt = "szyfr";

//        User u = new User("nowy");
//        try {
//            u.saveUserToFile();
//        } catch (IOException e) {
//            e.printStackTrace();
//        }


//        System.out.println("Encrypting...");
//        byte[] encrypted = new byte[0];
//        try {
//            encrypted = encrypt(toEncrypt, "password");
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//        String wynik = encrypted.toString();

        launch(args);
    }

//    public static byte[] encrypt(String toEncrypt, String key) throws Exception {
//
//
//        // generate key
//        KeyGenerator keyGen = KeyGenerator.getInstance("Twofish", "IAIK");
//        SecretKey secretKey = keyGen.generateKey();
//        // get Cipher and init it for encryption
//        Cipher cipher = Cipher.getInstance("Twofish/CBC/PKCS5Padding", "IAIK");
//        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
//        // encrypt data
//        byte[] zaszyyfrowac = toEncrypt.getBytes();
//        byte[] cipherText = cipher.doFinal(zaszyyfrowac);
//        // get the initialization vector from the cipher
//        byte[] ivBytes = cipher.getIV();
//        IvParameterSpec iv = new IvParameterSpec(ivBytes);
//
//        // raw key material (usually the key will be securely stored/transmitted)
//        byte[] keyBytes = secretKey.getEncoded();
//        // create a SecretKeySpec from key material
//        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "Twofish");
//        // get Cipher and init it for encryption
//        cipher = Cipher.getInstance("Twofish/CBC/PKCS5Padding", "IAIK");
//        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, iv);
//        byte[] plainText = cipher.doFinal(cipherText);
//
//        return plainText;
////        // create a binary key from the argument key (seed)
////        SecureRandom sr = new SecureRandom(key.getBytes());
////        KeyGenerator kg = KeyGenerator.getInstance("twofish");
////        kg.init(sr);
////        SecretKey sk = kg.generateKey();
////
////        // create an instance of cipher
////        Cipher cipher = Cipher.getInstance("twofish");
////
////        // initialize the cipher with the key
////        cipher.init(Cipher.ENCRYPT_MODE, sk);
////
////        // enctypt!
////        byte[] encrypted = cipher.doFinal(toEncrypt.getBytes());
////
////        return encrypted;
//    }


}
