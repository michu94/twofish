package sample;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.jws.soap.SOAPBinding;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;


/**
 * Created by Michuuuu on 2017-05-19.
 */
public class User {

    public String name;
    public byte[] privateKey;
    public byte[] publicKey;


    public  User(){}

    public User(String name, byte[] publicKey, byte[] privateKey){
        this.name = name;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public void saveUserToFile() throws IOException, TransformerException, ParserConfigurationException, InvalidKeySpecException, NoSuchAlgorithmException {


        //checking out the directories(if exists)
        File f = new File("privateKey");
        if (f.exists()) {
            System.out.println("nie tworze privateKey");
        } else
            new File("privateKey").mkdir();

        f = new File("publicKey");
        if (f.exists())
            System.out.println("nie tworze publicKey");
        else
            new File("publicKey").mkdir();


        //add public key to the file .\publicKey\name.key
        File file = new File("publicKey\\" + name.toString() + ".key");
        file.createNewFile();


        //dodawanie z XML
        XMLparser.XMLsaveKey("publicKey\\" + name.toString() + ".key",name.toString(),"RSA","PublicKey",publicKey);
        XMLparser.XMLsaveKeyNeat(name.toString() + ".key",name.toString(),"RSA","PublicKey",publicKey);
        String FILENAME = file.getAbsolutePath();
        FileOutputStream fos = new FileOutputStream(FILENAME,true);
//        fos.write(publicKey);
        fos.close();

        //add private key to the file .\privateKey\name.key
        file = new File("privateKey\\" + name.toString() + ".key");
        file.createNewFile();
        FILENAME = file.getAbsolutePath();
        fos = new FileOutputStream(FILENAME);
        fos.write(privateKey);

        fos.close();





    }


    @Override
    public String toString(){
        return this.name;
    }


}
