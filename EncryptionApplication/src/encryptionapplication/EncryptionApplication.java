/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package encryptionapplication;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import javafx.application.Application;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.Button;
import javafx.scene.control.TextField;
import javafx.scene.layout.Pane;
import javafx.scene.text.Text;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author blackspace
 */
public class EncryptionApplication extends Application {

    @Override
    public void start(Stage primaryStage) {
        Button enc = new Button();
        Button denc = new Button();
        enc.setText("Encryption");
        denc.setText("Decryption");
        enc.setLayoutX(270);
        enc.setLayoutY(150);
        denc.setLayoutX(270);
        denc.setLayoutY(180);

        Text text = new Text();
        text.setText("Please select your operation: ");
        text.setLayoutX(220);
        text.setLayoutY(130);

        enc.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {
                encryptionScreen();

            }
        });

        denc.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {
                decryptionScreen();

            }
        });

        Pane root = new Pane();
        root.getChildren().add(enc);
        root.getChildren().add(denc);
        root.getChildren().add(text);

        Scene scene = new Scene(root, 640, 400);

        primaryStage.setTitle("Encryption Application");
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        launch(args);
    }

    public void encryptionScreen() {
        Stage stage = new Stage();

        Button submitFile = new Button();
        submitFile.setText("Submit File");
        submitFile.setLayoutX(130);
        submitFile.setLayoutY(32);

        Button encrypt = new Button();
        encrypt.setText("Encrypt File");
        encrypt.setLayoutX(275);
        encrypt.setLayoutY(152);

        TextField key = new TextField();
        key.setLayoutX(120);
        key.setLayoutY(240);
        key.setPrefWidth(450);

        Text filePath = new Text();
        filePath.setText("");
        filePath.setLayoutX(130);
        filePath.setLayoutY(110);

        Text text = new Text();
        text.setText("Select your file: ");
        text.setLayoutX(20);
        text.setLayoutY(50);

        Text text2 = new Text();
        text2.setText("Selected file is: ");
        text2.setLayoutX(20);
        text2.setLayoutY(110);

        Text text3 = new Text();
        text3.setText("Press the button to encrypt your file: ");
        text3.setLayoutX(20);
        text3.setLayoutY(170);

        Alert alert = new Alert(AlertType.WARNING);
        alert.setTitle("Warning!");
        alert.setHeaderText("Warning!");
        alert.setContentText("Please submit a file.");

        Text text4 = new Text();
        text4.setText("Keep your key. You will use your key to decrypt your file. ");
        text4.setLayoutX(20);
        text4.setLayoutY(230);

        Text text5 = new Text();
        text5.setText("Your key is: ");
        text5.setLayoutX(20);
        text5.setLayoutY(260);

        submitFile.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {

                FileChooser fileChooser = new FileChooser();
                fileChooser.setTitle("Open Resource File");
                File file = fileChooser.showOpenDialog(stage);
                String filePath1 = file.getAbsolutePath();
                filePath.setText(filePath1);

            }
        });

        encrypt.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {
                if (!filePath.getText().equals("")) {

                    SecretKey secretKey = secretKey();
                    String keyString = decodeSecretKey(secretKey);
                    
                    key.setText(keyString);

                    File inputFile = new File(filePath.getText());
                    String ext = getFileExtension(inputFile);
                    File encryptedFile = new File(System.getProperty("user.home") + "/Desktop/" + "EncryptedFile." + ext);

                    try {
                        fileProcessor(Cipher.ENCRYPT_MODE, secretKey, inputFile, encryptedFile);
                    } catch (Exception ex) {
                        System.out.println(ex.getMessage());
                        ex.printStackTrace();
                    }
                } else {
                    alert.showAndWait();
                }
                
            }
        });

        Pane root = new Pane();

        root.getChildren().add(submitFile);
        root.getChildren().add(key);
        root.getChildren().add(filePath);
        root.getChildren().add(encrypt);
        root.getChildren().add(text);
        root.getChildren().add(text2);
        root.getChildren().add(text3);
        root.getChildren().add(text4);
        root.getChildren().add(text5);

        Scene scene = new Scene(root, 640, 400);
        stage.setTitle("Encryption");
        stage.setScene(scene);
        stage.show();
    }

    public void decryptionScreen() {
        Stage stage = new Stage();

        Button submitFile = new Button();
        submitFile.setText("Submit File");
        submitFile.setLayoutX(130);
        submitFile.setLayoutY(32);

        Button decrypt = new Button();
        decrypt.setText("Decrypt File");
        decrypt.setLayoutX(275);
        decrypt.setLayoutY(214);

        TextField key = new TextField();
        key.setText("");
        key.setLayoutX(120);
        key.setLayoutY(154);
        key.setPrefWidth(450);

        Text filePath = new Text();
        filePath.setText("");
        filePath.setLayoutX(130);
        filePath.setLayoutY(110);

        Text text = new Text();
        text.setText("Select your file: ");
        text.setLayoutX(20);
        text.setLayoutY(50);

        Text text2 = new Text();
        text2.setText("Selected file is: ");
        text2.setLayoutX(20);
        text2.setLayoutY(110);

        Text text3 = new Text();
        text3.setText("Put your key: ");
        text3.setLayoutX(20);
        text3.setLayoutY(170);

        Text text4 = new Text();
        text4.setText("Press the button to encrypt your file: ");
        text4.setLayoutX(20);
        text4.setLayoutY(230);

        Alert alert = new Alert(AlertType.WARNING);
        alert.setTitle("Warning!");
        alert.setHeaderText("Warning!");
        alert.setContentText("Please submit a file.");

        Alert alert2 = new Alert(AlertType.WARNING);
        alert2.setTitle("Warning!");
        alert2.setHeaderText("Warning!");
        alert2.setContentText("Please enter a key.");

        submitFile.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {

                FileChooser fileChooser = new FileChooser();
                fileChooser.setTitle("Open Resource File");
                File file = fileChooser.showOpenDialog(stage);
                String filePath1 = file.getAbsolutePath();

                filePath.setText(filePath1);

            }
        });

        decrypt.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {

                if (filePath.getText().equals("")) {
                    alert.showAndWait();
                } else if (key.getText().equals("")) {
                    alert2.showAndWait();
                } else {
                    String keyS = key.getText();

                    SecretKey secretkey = encodeSecretKey(keyS);

                    File encryptedFile = new File(filePath.getText());
                    String ext = getFileExtension(encryptedFile);
                    File decryptedFile = new File(System.getProperty("user.home") + "/Desktop/" + "DecryptedFile."+ ext);

                    fileProcessor(Cipher.DECRYPT_MODE, secretkey, encryptedFile, decryptedFile);
                }
            }
        });

        Pane root = new Pane();

        root.getChildren().add(submitFile);
        root.getChildren().add(key);
        root.getChildren().add(filePath);
        root.getChildren().add(decrypt);
        root.getChildren().add(text);
        root.getChildren().add(text2);
        root.getChildren().add(text3);
        root.getChildren().add(text4);

        Scene scene = new Scene(root, 640, 400);
        stage.setTitle("Decryption");
        stage.setScene(scene);
        stage.show();
    }


    public static SecretKey secretKey() {
        SecretKey myDesKey = null;
        try {
            KeyGenerator keygenerator = KeyGenerator.getInstance("AES");
            SecureRandom secureRandom = new SecureRandom();
            int keyBitSize = 256;

            keygenerator.init(keyBitSize, secureRandom);

            myDesKey = keygenerator.generateKey();

        } catch (Exception e) {
            System.out.println("Exception");
        }
        return myDesKey;
    }

    public static String decodeSecretKey(SecretKey key) {

        byte encoded[] = key.getEncoded();
        String encodedKey = Base64.getEncoder().encodeToString(encoded);

        return encodedKey;
    }

    public static SecretKey encodeSecretKey(String key) {
        SecretKey originalKey = null;
        try {

            byte[] decodedKey = Base64.getDecoder().decode(key);

            originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

        } catch (Exception e) {
            System.out.println("Exception");
        }

        return originalKey;
    }

    static void fileProcessor(int cipherMode, SecretKey key, File inputFile, File outputFile) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(cipherMode, key);

            FileInputStream inputStream = new FileInputStream(inputFile);
            byte[] inputBytes = new byte[(int) inputFile.length()];
            inputStream.read(inputBytes);

            byte[] outputBytes = cipher.doFinal(inputBytes);

            FileOutputStream outputStream = new FileOutputStream(outputFile);
            outputStream.write(outputBytes);

            inputStream.close();
            outputStream.close();

        } catch (NoSuchPaddingException | NoSuchAlgorithmException
                | InvalidKeyException | BadPaddingException
                | IllegalBlockSizeException | IOException e) {
            e.printStackTrace();
        }
    }

    private static String getFileExtension(File file) {
        String fileName = file.getName();
        if (fileName.lastIndexOf(".") != -1 && fileName.lastIndexOf(".") != 0) {
            return fileName.substring(fileName.lastIndexOf(".") + 1);
        } else {
            return "";
        }
    }

}
