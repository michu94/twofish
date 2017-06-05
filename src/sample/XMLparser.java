package sample;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

/**
 * Created by Michuuuu on 2017-05-23.
 */
public class XMLparser {

    static public void XMLsaveKey(String outFile, String user, String alg,String keyType, byte[] key ) throws ParserConfigurationException, TransformerException, IOException {

        DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder docBuilder = docFactory.newDocumentBuilder();

        // root elements
        Document doc = docBuilder.newDocument();
        Element rootElement = doc.createElement(keyType);
        doc.appendChild(rootElement);

        Element algorithm = doc.createElement("Algorithm");
        algorithm.appendChild(doc.createTextNode(alg));
        rootElement.appendChild(algorithm);

        Element userElement = doc.createElement("UserName");
        userElement.appendChild(doc.createTextNode(user));
        rootElement.appendChild(userElement);


        // write the content into xml file
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        //transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        //transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(outFile);

        transformer.transform(source, result);
        File f1 = new File(outFile);
        PrintWriter pw = new PrintWriter(new FileOutputStream(f1, true));
        pw.println();
        pw.close();
        FileOutputStream fos = new FileOutputStream(f1,true);
        fos.write(key);
        fos.close();


    }


    static public void XMLsaveKeyNeat(String outFile, String user, String alg,String keyType, byte[] key ) throws ParserConfigurationException, TransformerException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {


        File f = new File("data");
        if (f.exists()) {
            System.out.println("nie tworze data");
        } else
            new File("data").mkdir();

        f = new File("data\\publicKey");
        if (f.exists())
            System.out.println("nie tworze publicKey");
        else
            new File("data\\publicKey").mkdir();

        DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder docBuilder = docFactory.newDocumentBuilder();

        // root elements
        Document doc = docBuilder.newDocument();
        Element rootElement = doc.createElement(keyType);
        doc.appendChild(rootElement);

        Element algorithm = doc.createElement("Algorithm");
        algorithm.appendChild(doc.createTextNode(alg));
        rootElement.appendChild(algorithm);

        Element userElement = doc.createElement("UserName");
        userElement.appendChild(doc.createTextNode(user));
        rootElement.appendChild(userElement);


        // write the content into xml file
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult("data\\publicKey\\"+outFile);

        transformer.transform(source, result);
        File f1 = new File("data\\publicKey\\"+outFile);
        PrintWriter pw = new PrintWriter(new FileOutputStream(f1, true));
        pw.println();
        pw.close();
        FileOutputStream fos = new FileOutputStream(f1,true);
        fos.write(key);
        fos.close();


    }

    static public void XMLcreateHeader(String outFile, List<User> users, String keySiz, String blockSiz, String cipherMod, byte[] vectorIV, Map<String,byte[]> sessionKeyList, String subBl) throws ParserConfigurationException, TransformerException, FileNotFoundException {


        DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder docBuilder = docFactory.newDocumentBuilder();

        // root elements
        Document doc = docBuilder.newDocument();
        Element rootElement = doc.createElement("EncryptedFileHeader");
        doc.appendChild(rootElement);

        Element algorithm = doc.createElement("Algorithm");
        algorithm.appendChild(doc.createTextNode("Twofish"));
        rootElement.appendChild(algorithm);

        Element keySize = doc.createElement("KeySize");
        keySize.appendChild(doc.createTextNode(keySiz));
        rootElement.appendChild(keySize);

        Element blockSize = doc.createElement("BlockSize");
        blockSize.appendChild(doc.createTextNode(blockSiz));
        rootElement.appendChild(blockSize);

        Element cipherMode = doc.createElement("CipherMode");
        cipherMode.appendChild(doc.createTextNode(cipherMod));
        rootElement.appendChild(cipherMode);

        if(!cipherMod.equals("ECB")){
            Element iv = doc.createElement("IV");
            iv.appendChild(doc.createTextNode(Base64.getEncoder().encodeToString(vectorIV)));
            rootElement.appendChild(iv);
        }
        if(cipherMod.equals("OFB") || cipherMod.equals("CFB")){
            Element subBlock = doc.createElement("SegmentSize");
            subBlock.appendChild(doc.createTextNode(subBl));
            rootElement.appendChild(subBlock);
        }

        Element approvedUsers = doc.createElement("ApprovedUsers");
        rootElement.appendChild(approvedUsers);

        for( User u : users){
            Element userElement = doc.createElement("User");
            approvedUsers.appendChild(userElement);

            Element name = doc.createElement("Name");
            name.appendChild(doc.createTextNode(u.name));
            userElement.appendChild(name);

            Element sessionKeyElement = doc.createElement("SessionKey");
            sessionKeyElement.appendChild(doc.createTextNode(Base64.getEncoder().encodeToString(sessionKeyList.get(u.name))));
            userElement.appendChild(sessionKeyElement);
        }


        // write the content into xml file
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();

        //DoXML
        //transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        //transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(outFile);

        transformer.transform(source, result);
        File f1 = new File(outFile);
        PrintWriter pw = new PrintWriter(new FileOutputStream(f1, true));
        pw.println();
        pw.close();

    }


    static public void XMLcreateHeaderNeat(String outFile, List<User> users, String keySiz, String blockSiz, String cipherMod, byte[] vectorIV, Map<String,byte[]> sessionKeyList, String subBl) throws ParserConfigurationException, TransformerException, FileNotFoundException {

        File f = new File("data");
        if (f.exists()) {
            System.out.println("nie tworze data");
        } else
            new File("data").mkdir();

        f = new File("data\\encryptedFiles");
        if (f.exists())
            System.out.println("nie tworze publicKey");
        else
            new File("data\\encryptedFiles").mkdir();
        DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder docBuilder = docFactory.newDocumentBuilder();

        // root elements
        Document doc = docBuilder.newDocument();
        Element rootElement = doc.createElement("EncryptedFileHeader");
        doc.appendChild(rootElement);

        Element algorithm = doc.createElement("Algorithm");
        algorithm.appendChild(doc.createTextNode("Twofish"));
        rootElement.appendChild(algorithm);

        Element keySize = doc.createElement("KeySize");
        keySize.appendChild(doc.createTextNode(keySiz));
        rootElement.appendChild(keySize);

        Element blockSize = doc.createElement("BlockSize");
        blockSize.appendChild(doc.createTextNode(blockSiz));
        rootElement.appendChild(blockSize);

        Element cipherMode = doc.createElement("CipherMode");
        cipherMode.appendChild(doc.createTextNode(cipherMod));
        rootElement.appendChild(cipherMode);

        if(!cipherMod.equals("ECB")){
            Element iv = doc.createElement("IV");
            iv.appendChild(doc.createTextNode(Base64.getEncoder().encodeToString(vectorIV)));
            rootElement.appendChild(iv);
        }
        if(cipherMod.equals("OFB") || cipherMod.equals("CFB")){
            Element subBlock = doc.createElement("SegmentSize");
            subBlock.appendChild(doc.createTextNode(subBl));
            rootElement.appendChild(subBlock);
        }

        Element approvedUsers = doc.createElement("ApprovedUsers");
        rootElement.appendChild(approvedUsers);

        for( User u : users){
            Element userElement = doc.createElement("User");
            approvedUsers.appendChild(userElement);

            Element name = doc.createElement("Name");
            name.appendChild(doc.createTextNode(u.name));
            userElement.appendChild(name);

            Element sessionKeyElement = doc.createElement("SessionKey");
            sessionKeyElement.appendChild(doc.createTextNode(Base64.getEncoder().encodeToString(sessionKeyList.get(u.name))));
            userElement.appendChild(sessionKeyElement);
        }


        // write the content into xml file
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();

        //DoXML
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult("data\\encryptedFiles\\"+outFile);

        transformer.transform(source, result);
        File f1 = new File("data\\encryptedFiles\\"+outFile);
        PrintWriter pw = new PrintWriter(new FileOutputStream(f1, true));
        pw.println();
        pw.close();

    }

    static public String XMLgetElement(File inFile,String element) throws ParserConfigurationException, IOException, SAXException {

        File fXmlFile = inFile;

        FileInputStream fis = new FileInputStream(fXmlFile);
        Scanner scanner = new Scanner(fis);
        String line = scanner.nextLine();
//        String test = line;
//        //test do XML
//        boolean a =!test.equals("</PublicKey>") ^ !test.equals("</EncryptedFileHeader>");
//        while (!a){
//            test = scanner.nextLine();
//            line += test;
//            a =!test.equals("</PublicKey>") ^ !test.equals("</EncryptedFileHeader>");
//        }
//        line += scanner.nextLine();
        //koniec test


        //int skip = line.getBytes().length + 1;
        scanner.close();
        fis.close();

        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        //dbFactory.setValidating(false);
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        InputSource is = new InputSource(new StringReader(line));
        Document doc = dBuilder.parse(is);
        String ret = "";

        Node node = doc.getFirstChild();
        NodeList nodeList = node.getChildNodes();
        for(int i=0; i< nodeList.getLength();i++){
            Node n = nodeList.item(i);
            if(n.getNodeName().equals(element)){
                ret = n.getTextContent();
                break;
            }

        }

        return ret;
    }
    static  public byte[] XMLgetSessionKey(File inFile,User u) throws IOException, ParserConfigurationException, SAXException {
        File fXmlFile = inFile;

        FileInputStream fis = new FileInputStream(fXmlFile);
        Scanner scanner = new Scanner(fis);

        String line = scanner.nextLine();
//        String test = line;
//        //test do XML
//        boolean a =!test.equals("</PublicKey>") ^ !test.equals("</EncryptedFileHeader>");
//        while (!a){
//            test = scanner.nextLine();
//            line += test;
//            a =!test.equals("</PublicKey>") ^ !test.equals("</EncryptedFileHeader>");
//        }
//        line += scanner.nextLine();
        //koniec test




        //int skip = line.getBytes().length + 1;
        scanner.close();
        fis.close();

        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        //dbFactory.setValidating(false);
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        InputSource is = new InputSource(new StringReader(line));
        Document doc = dBuilder.parse(is);
        String ret = "";

        Node node = doc.getFirstChild();
        NodeList nodeList = node.getChildNodes();
        for(int i=0; i< nodeList.getLength();i++){
            Node n = nodeList.item(i);
            if(n.getNodeName().equals("ApprovedUsers")){

                NodeList nodeList2 = n.getChildNodes();
                for(int j = 0;j<nodeList2.getLength();j++){
                    Node m = nodeList2.item(j);
                    if(m.getFirstChild().getTextContent().equals(u.name)){
                        ret = m.getFirstChild().getNextSibling().getTextContent();
                        break;
                    }
                }
            }

        }

        return Base64.getDecoder().decode(ret);

    }

    static public int XMLhowManyToSkip(File f) throws IOException {
        File fXmlFile = f;

        FileInputStream fis = new FileInputStream(fXmlFile);
        Scanner scanner = new Scanner(fis);
        String line = scanner.nextLine();

        //DoXML
//        boolean a =!line.equals("</PublicKey>") ^ !line.equals("</EncryptedFileHeader>");
//        int skip = 1;
//        while (!a){
//            line = scanner.nextLine();
//            a =!line.equals("</PublicKey>") ^ !line.equals("</EncryptedFileHeader>");
//            skip += line.getBytes().length;
//        }

        int skip = line.getBytes().length + 1;
        scanner.close();
        fis.close();

        return skip;
    }

    static public int XMLhowManyToSkip2(File f) throws IOException {
        File fXmlFile = f;

        FileInputStream fis = new FileInputStream(fXmlFile);
        Scanner scanner = new Scanner(fis);
        String line = scanner.nextLine();

        //DoXML
        boolean a =!line.equals("</PublicKey>") ^ !line.equals("</EncryptedFileHeader>");
        int skip = 1;
        while (!a){
            line = scanner.nextLine();
            a =!line.equals("</PublicKey>") ^ !line.equals("</EncryptedFileHeader>");
            skip += line.getBytes().length;
        }

        //int skip = line.getBytes().length + 1;
        scanner.close();
        fis.close();

        return skip;
    }

    static public List<String> XMLgetDecryptUsers(File f) throws IOException, SAXException, ParserConfigurationException {

        List<String> toRet = new ArrayList<>();


        FileInputStream fis = new FileInputStream(f);
        Scanner scanner = new Scanner(fis);
        String line = scanner.nextLine();
        scanner.close();
        fis.close();

        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        //dbFactory.setValidating(false);
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        InputSource is = new InputSource(new StringReader(line));
        Document doc = dBuilder.parse(is);

        NodeList nodeList1 = doc.getElementsByTagName("*");

        for (int i = 0; i < nodeList1.getLength(); i++) {
            Node node = nodeList1.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE) {
                // do something with the current element
                if(node.getNodeName().equals("Name"))
                    toRet.add(node.getTextContent());
                System.out.println(node.getNodeName());
            }
        }


        return toRet;
    }

}
