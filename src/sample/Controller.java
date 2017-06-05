package sample;

import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.xml.sax.SAXException;

import javax.crypto.*;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import java.io.*;
import java.net.URL;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Controller implements Initializable{


    @FXML
    Button odszyfruj;

    @FXML
    Button wejscie;
    @FXML
    Button wyjscie;

    @FXML
    TextArea inFile;
    @FXML
    TextField inFileEncoded;
    @FXML
    TextField outFileEncoded;
    @FXML
    TextField userPassWordTextField;
    @FXML
    TextArea outFile;

    @FXML
    public ListView usersListView;
    @FXML
    public  ListView usersListView2;
    @FXML
    ComboBox cipherModeComboBox;
    @FXML
    ComboBox keyLengthComboBox;
    @FXML
    ComboBox blockSizeComboBox;

    @FXML
    ProgressBar progressBar;

    @FXML
    ProgressBar progressBar2;


    @FXML
    TextArea publicKeyTextArea;
    @FXML
    TextField userNameTextField;

    public static ObservableList<User> usersList2;
    public static ObservableList<User> usersList;
    public ObservableList<String> keyLengthList;
    public ObservableList<String> cipherModeList;
    public ObservableList<String> blockSizeList;

    File fPub;
    Twofish tf;
    Cipher cip;
    File f1;
    File f2;
    @FXML
    public File wczytajPlik(){

        FileChooser fc = new FileChooser();
        fc.setInitialDirectory(new File("."));
        File f = fc.showOpenDialog(null);
        if(f != null)
            inFile.setText(f.toString());
        f1=f;
        return f;
    }

    @FXML
    public File wybierzPlik() throws ParserConfigurationException, SAXException, IOException {
        int n;
        FileChooser fc = new FileChooser();
        fc.setInitialDirectory(new File("."));
        File f = fc.showOpenDialog(null);
        if(f != null){
            inFileEncoded.setText(f.toString());

            //tutaj dodac dodawanie userow do listy
            //XMLparser.XMLgetDecryptUsers(f);
            addDecryptUsers(f);

        }
        f2=f;

        return f;
    }

    @FXML
    public  void wybierzPlikEncrypt() throws ParserConfigurationException, SAXException, IOException {
        FileChooser fc = new FileChooser();
        fc.setInitialDirectory(new File("."));
        File f = fc.showOpenDialog(null);
        if(f != null){
            outFile.setText(f.toString());
        }
    }

    @FXML
    public void wybierzPlikDecrypt() throws ParserConfigurationException, SAXException, IOException {
        FileChooser fc = new FileChooser();
        fc.setInitialDirectory(new File("."));
        File f = fc.showOpenDialog(null);
        if(f != null){
            outFileEncoded.setText(f.toString());

        }


    }

    @FXML
    public void zakoduj() throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeyException, IOException, InvalidKeySpecException, ShortBufferException, TransformerException, ParserConfigurationException {

        if(!validateFieldsEncryption())
            return;
        File file = f1;
        //User u = (User)usersListView.getSelectionModel().getSelectedItem();
        List<User> users = (List<User>) usersListView.getSelectionModel().getSelectedItems();
        String outName = outFile.getText();
        String cipherMode = (String)cipherModeComboBox.getSelectionModel().getSelectedItem();
        String subBlockSize = (String)blockSizeComboBox.getSelectionModel().getSelectedItem();
        String keylen = (String)keyLengthComboBox.getSelectionModel().getSelectedItem();
        Twofish.encrypt(file,users,outName,cipherMode,keylen,subBlockSize,progressBar);

    }

    @FXML
    public void odkoduj() throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeyException, IOException, InvalidKeySpecException, ShortBufferException, ParserConfigurationException, SAXException, TransformerException, InterruptedException {

        if(!validateFieldsDecryption())
            return;
        File file = f2;
        String outName = outFileEncoded.getText();
        String pw = userPassWordTextField.getText();
        User u = (User)usersListView2.getSelectionModel().getSelectedItem();
        try{
            Twofish.decrypt(file,pw,u,outName,progressBar2);
        }catch(javax.crypto.BadPaddingException e){

            //Twofish.decryptWithBadPW(file,pw,u,outName,progressBar2);
                //to dziala
//            List<User> l = new ArrayList<User>();
//            l.add(u);
//            Twofish.encrypt(file,l,outName,"ECB","128","2",progressBar2);
//            Thread.sleep(1000);
//            moveFileTo(outName);

            Twofish.decryptWithBadPW(file,pw,u,outName,progressBar2);
        }



    }

    @FXML
    public void addUser(){
        try {
            FXMLLoader fxmlLoader = new FXMLLoader();
            fxmlLoader.setLocation(getClass().getResource("addUser.fxml"));

            Parent root1 = (Parent) fxmlLoader.load();

            //dodanie list do kontrolera
            AddUserController controller = fxmlLoader.<AddUserController>getController();
            controller.setUserList(usersList);
            controller.setUserList2(usersList2);

            Stage stage = new Stage();
            stage.setScene(new Scene(root1));
            stage.setTitle("Dodanie użytkownika");
            stage.show();
        } catch (IOException e) {
            Logger logger = Logger.getLogger(getClass().getName());
            logger.log(Level.SEVERE, "Failed to create new Window.", e);
        }

    }
    @FXML
    public void removeUser(){

        User u = (User)usersListView.getSelectionModel().getSelectedItem();
        if(u == null)
            return;
        File f = new File(".\\publicKey\\"+u.name+".key");
        File f2 = new File(".\\privateKey\\"+u.name+".key");
        boolean isdelete = true;
        if(f.exists() && f.isFile())
            isdelete = f.delete();
        if(f2.exists() && f2.isFile())
            isdelete = f2.delete();

        usersList.remove(u);
    }
    private void loadUsers() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        File folder = new File("publicKey");
        File[] listOfFiles = folder.listFiles();

        List<String> listOfNames = new ArrayList<String>();

        //pobranie wszystkich uzytkownikow
        for (File file : listOfFiles) {
            if (file.isFile())
                listOfNames.add(file.getName().split("\\.")[0]) ;
        }

        usersList = FXCollections.observableArrayList();
        //
        for (String user : listOfNames){
            File pubKeyFile = new File("publicKey\\"+user+".key");
            File privKeyFile = new File("privateKey\\"+user+".key");
            User u = null;
            //pobieranie klucza prywatnego
            if(privKeyFile.exists()){
                RandomAccessFile f = new RandomAccessFile(privKeyFile, "r");
                byte[] privateKeyBytes = new byte[(int)f.length()];
                f.readFully(privateKeyBytes);
                f.close();
                //pobieranie klucza publicznego
//                f = new RandomAccessFile(pubKeyFile, "r");
//                byte[] publicKeyBytes = new byte[(int)f.length()];
//                f.readFully(publicKeyBytes);



                //DoXML
                //prywatny klucz
//                RandomAccessFile f = new RandomAccessFile(privKeyFile, "r");
//                byte[] privateKeyBytes = new byte[(int)f.length()];
//                f.readFully(privateKeyBytes);
//                f.close();
//                //pobieranie klucza publicznego
                f = new RandomAccessFile(pubKeyFile, "r");
                int skiper = XMLparser.XMLhowManyToSkip(pubKeyFile) + 1;
                byte[] publicKeyBytes = new byte[(int)f.length() - skiper];
                f.skipBytes(skiper);
                f.readFully(publicKeyBytes);

                f.close();
                u = new User(user,publicKeyBytes,privateKeyBytes);
            }else{
                RandomAccessFile f;

                //pobieranie klucza publicznego
                f = new RandomAccessFile(pubKeyFile, "r");
                byte[] publicKeyBytes = new byte[(int)f.length()];
                f.readFully(publicKeyBytes);


                f.close();
                u = new User(user,publicKeyBytes,null);
            }


            usersList.add(u);

        }

        usersListView.setItems(usersList);
        //usersListView2.setItems(usersList);


    }

    public void addDecryptUsers(File file) throws ParserConfigurationException, SAXException, IOException {



        List<String> listOfNames = XMLparser.XMLgetDecryptUsers(file);
        usersList2 = FXCollections.observableArrayList();

        for (String user : listOfNames){
            File pubKeyFile = new File("publicKey\\"+user+".key");
            File privKeyFile = new File("privateKey\\"+user+".key");
            User u = null;
            //pobieranie klucza prywatnego

            RandomAccessFile f = new RandomAccessFile(privKeyFile, "r");
            byte[] privateKeyBytes = new byte[(int)f.length()];
            f.readFully(privateKeyBytes);
            f.close();
            //pobieranie klucza publicznego
//                f = new RandomAccessFile(pubKeyFile, "r");
//                byte[] publicKeyBytes = new byte[(int)f.length()];
//                f.readFully(publicKeyBytes);

            //test z XML
            f = new RandomAccessFile(pubKeyFile, "r");
            int skiper = XMLparser.XMLhowManyToSkip(pubKeyFile) + 1;
            byte[] publicKeyBytes = new byte[(int)f.length() - skiper];
            f.skipBytes(skiper);
            f.readFully(publicKeyBytes);

            f.close();
            u = new User(user,publicKeyBytes,privateKeyBytes);

            usersList2.add(u);

        }


        usersListView2.setItems(usersList2);
        usersListView2.setDisable(false);



    }



//    private void loadUsersToDecrypt() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
//
//        File folder = new File("privateKey");
//        File[] listOfFiles = folder.listFiles();
//
//        List<String> listOfNames = new ArrayList<String>();
//
//        //pobranie wszystkich uzytkownikow
//        for (File file : listOfFiles) {
//            if (file.isFile())
//                listOfNames.add(file.getName().split("\\.")[0]) ;
//        }
//
//        usersList2 = FXCollections.observableArrayList();
//        //
//        for (String user : listOfNames){
//            File pubKeyFile = new File("publicKey\\"+user+".key");
//            File privKeyFile = new File("privateKey\\"+user+".key");
//            User u = null;
//            //pobieranie klucza prywatnego
//
//                RandomAccessFile f = new RandomAccessFile(privKeyFile, "r");
//                byte[] privateKeyBytes = new byte[(int)f.length()];
//                f.readFully(privateKeyBytes);
//                f.close();
//                //pobieranie klucza publicznego
////                f = new RandomAccessFile(pubKeyFile, "r");
////                byte[] publicKeyBytes = new byte[(int)f.length()];
////                f.readFully(publicKeyBytes);
//
//                //test z XML
//                f = new RandomAccessFile(pubKeyFile, "r");
//                int skiper = XMLparser.XMLhowManyToSkip(pubKeyFile) + 1;
//                byte[] publicKeyBytes = new byte[(int)f.length() - skiper];
//                f.skipBytes(skiper);
//                f.readFully(publicKeyBytes);
//
//
//                f.close();
//                u = new User(user,publicKeyBytes,privateKeyBytes);
//
//
//            usersList2.add(u);
//
//        }
//
//
//        usersListView2.setItems(usersList2);
//
//
//    }

    public void loadCipherModes(){

        cipherModeList = FXCollections.observableArrayList("ECB", "CFB", "CBC", "OFB");
        cipherModeComboBox.setItems(cipherModeList);
        cipherModeComboBox.setValue("ECB");
    }
    public void loadKeyLengths(){
        keyLengthList = FXCollections.observableArrayList("128","136","144","152","160","168","176","184","192","200","208","216","224","232","240","248","256");
        keyLengthComboBox.setItems(keyLengthList);
        keyLengthComboBox.setValue("128");
    }
    public void loadBlockSize(){
        blockSizeList = FXCollections.observableArrayList("8","16","32","64");
        blockSizeComboBox.setItems(blockSizeList);
        blockSizeComboBox.setValue("8");
    }

    @Override
    public void initialize(URL location, ResourceBundle resources) {

        //ladowanie listy uzytkownikow
        try {
            loadUsers();
            //loadUsersToDecrypt();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        usersListView.getSelectionModel().setSelectionMode(SelectionMode.MULTIPLE);
        inFile.setDisable(true);
        inFileEncoded.setDisable(true);
        usersListView2.setDisable(true);
        //ladowanie trybów pracy
        loadCipherModes();
        //ladowanie dlugosci klucza
        loadKeyLengths();
        //ladowanie dlugosci bloku
        loadBlockSize();

        blockSizeComboBox.setDisable(true);
        publicKeyTextArea.setDisable(true);
        cipherModeComboBox.valueProperty().addListener(new ChangeListener() {
            @Override
            public void changed(ObservableValue observable, Object oldValue, Object newValue) {

                if(observable.getValue().equals("ECB") || observable.getValue().equals("CBC"))
                    blockSizeComboBox.setDisable(true);
                else
                    blockSizeComboBox.setDisable(false);

            }
        });


    }

    @FXML
    public File selectPublicKey(){

        FileChooser fc = new FileChooser();
        File f = fc.showOpenDialog(null);
        int k;
        if(f != null)
            publicKeyTextArea.setText(f.toString());
        fPub=f;
        return f;
    }

    public void addPublicKey() throws IOException {

        if(!validateFieldsImportPublicKey())
            return;
        String publicKeyFile = publicKeyTextArea.getText();
        String userName = userNameTextField.getText();

        File f = new File("publicKey");
        if (f.exists())
            System.out.println("nie tworze publicKey");
        else
            new File("publicKey").mkdir();

        File files = new File(publicKeyFile);

        RandomAccessFile fa = new RandomAccessFile(files, "r");
        int skiper = XMLparser.XMLhowManyToSkip(files) + 1;
        byte[] publicKey = new byte[(int)fa.length() - skiper];
        fa.skipBytes(skiper);
        fa.readFully(publicKey);

//        FileInputStream fis = new FileInputStream(files);
//        byte[] publicKey = new byte[(int)files.length()];
//        fis.read(publicKey);

        File file = new File("publicKey\\" + userName.toString() + ".key");
        file.createNewFile();
        FileOutputStream fos = new FileOutputStream(file.getAbsolutePath());
        fos.write(publicKey);

        fa.close();
        //fis.close();
        fos.close();

        User u = new User(userName,publicKey,null);
        usersList.add(u);


    }
    private boolean validateFieldsEncryption(){

        if(inFile.getText().equals("")){
            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setTitle("Puste pole");
            alert.setContentText("Wybierz plik wejściowy !!!");

            alert.showAndWait();
            return false;
        }else if(outFile.getText().equals("")){
            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setTitle("Puste pole");
            alert.setContentText("Podaj nazwę pliku zaszyfrowanego !!!");

            alert.showAndWait();
            return false;
        }else if (usersListView.getSelectionModel().getSelectedItem() == null){
            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setTitle("Brak użytkowanika");
            alert.setContentText("Wybierz użytkownika z listy!!!");

            alert.showAndWait();
            return false;
        }
        else
            return true;


    }
    public boolean validateFieldsImportPublicKey(){

        if(publicKeyTextArea.getText().equals("")){
            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setTitle("Puste pole");
            alert.setContentText("Wybierz plik do zaimportowania!!!");

            alert.showAndWait();
            return false;
        }else if(userNameTextField.getText().equals("")){
            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setTitle("Puste pole");
            alert.setContentText("Podaj nazwe użytkownika !!!");

            alert.showAndWait();
            return false;
        }else
            return true;
    }
    public boolean validateFieldsDecryption(){

        if(inFileEncoded.getText().equals("")){
            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setTitle("Puste pole");
            alert.setContentText("Wybierz plik wejściowy do odszyfrowania!!!");

            alert.showAndWait();
            return false;
        }else if(outFileEncoded.getText().equals("")){
            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setTitle("Puste pole");
            alert.setContentText("Podaj nazwę pliku odszyfrowanego !!!");

            alert.showAndWait();
            return false;
        }else if(userPassWordTextField.getText().equals("")){
            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setTitle("Puste pole");
            alert.setContentText("Podaj haslo do odszyfrowania!!!");

            alert.showAndWait();
            return false;
        }else if(usersListView2.getSelectionModel().getSelectedItem() == null){
            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setTitle("Brak odbiorcy");
            alert.setContentText("Wybierz odbiorce z listy!!!");

            alert.showAndWait();
            return false;
        }else
            return true;

    }


    private void moveFileTo(String name){

        InputStream inStream = null;
        OutputStream outStream = null;

        try{

            File afile =new File(".\\encryptedFiles\\"+name+".enc");
            File bfile =new File("decryptedFiles\\"+name);

            inStream = new FileInputStream(afile);
            outStream = new FileOutputStream(bfile);

            byte[] buffer = new byte[1024];

            int length;
            //copy the file content in bytes
            while ((length = inStream.read(buffer)) > 0){

                outStream.write(buffer, 0, length);

            }

            inStream.close();
            outStream.close();

            //delete the original file
            afile.delete();


        }catch(IOException e){
            e.printStackTrace();
        }
    }
}
