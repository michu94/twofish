package sample;

import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.TextField;
import javafx.stage.Stage;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

/**
 * Created by Michuuuu on 2017-05-21.
 */
public class AddUserController {

    @FXML
    private TextField userNameField;
    @FXML
    private  TextField userPasswordField;
    @FXML
    private TextField userSecondPassField;

    @FXML
    private Button addButton;

    private ObservableList<User> listOfUsers;
    private ObservableList<User> listOfUsers2;
    @FXML
    public void addUser() throws NoSuchProviderException, NoSuchAlgorithmException, IOException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, TransformerException, ParserConfigurationException, InvalidKeySpecException {
        String name = userNameField.getText();
        String pass = userPasswordField.getText();
        String pass2 = userSecondPassField.getText();

        if(name.equals("") || pass.equals("") || pass2.equals("")){
            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setTitle("Puste pole");
            alert.setContentText("Uzupełnij wszystkie pola !");

            alert.showAndWait();
            return;
        }

        //jesli bledne haslo
        if(!pass.equals(pass2)){
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle("Błędne haslo");
            alert.setHeaderText("Hasła muszą się zgadzać");
            alert.setContentText("Podaj dwa takie same hasła !");

            alert.showAndWait();
            return;
        }



        KeyPair keyPair = Twofish.getRSAkeys();



        byte[] hashPW = Twofish.getHashFromPW(pass);
        byte[] encryptedPW = Twofish.encrypt(hashPW,keyPair.getPrivate());
        User user = new User(name,keyPair.getPublic().getEncoded(),encryptedPW);
        listOfUsers.add(user);
        //listOfUsers2.add(user);
        user.saveUserToFile();

        Stage stage = (Stage) addButton.getScene().getWindow();
        stage.close();

    }

    public void setUserList(ObservableList<User> l){
        this.listOfUsers = l;
    }
    public void setUserList2(ObservableList<User> l){
        this.listOfUsers2 = l;
    }


}


