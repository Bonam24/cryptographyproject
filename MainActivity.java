package com.example.alicepart;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.SecureRandom;

public class MainActivity extends AppCompatActivity {
    //declaration of variables
TextView tvalice,tvoutbob,tvmode,tvinalice,tvinciph,ciphertext1,tvinmess;
EditText edmode,edoutmess,edinmess;
Button button2,button3;
private  boolean choose=false;
private  int serverport = 1234;//serrver port
private String servername = "10.66.32.198";//server ip
private  String mess;
private  Integer x=0;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        //registering textviews
        tvalice = findViewById(R.id.tvalice);
        tvoutbob = findViewById(R.id.tvoutbob);
        tvinalice = findViewById(R.id.tvinalice);
        tvinciph = findViewById(R.id.tvinciph);
        tvinmess = findViewById(R.id.tvinmess);
        tvmode = findViewById(R.id.tvmode);
        ciphertext1 = findViewById(R.id.ciphertext1);

        //registering edittexttexts
        edoutmess = findViewById(R.id.edoutmess);
        edmode = findViewById(R.id.edmode);
        edinmess = findViewById(R.id.edinmess);
        //registering buttons

        button2 = findViewById(R.id.button2);
        button3 = findViewById(R.id.button3);
        //button and function to toggle receive and send modes
        button2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                if(x%2==0){
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            edmode.setText("Send mode");
                            choose=true;
                        }
                    });
                }
                else {
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            edmode.setText("Receive mode");
                            choose=false;
                        }
                    });
                }
               x++;
            }
        });
        //connect to server(BOB) button and its functions
        button3.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try{
                            //creating serversocket which will connect to BOB
                            Socket socket = new Socket(servername,serverport);
                            //function to receive message from BOB
                            if(!choose){

                                BufferedReader br_input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                                String ciphertext = br_input.readLine();
                                String mod = br_input.readLine();
                                String phi = br_input.readLine();
                                String pubkey = br_input.readLine();
                                BigInteger cip = new BigInteger(ciphertext);
                                BigInteger modn = new BigInteger(mod);
                                BigInteger phil = new BigInteger(phi);
                                BigInteger pubk = new BigInteger(pubkey);
                                BigInteger privkey = pubk.modInverse(phil);
                                int keySize = 1024;
                                RSAKeyPair keyPair = generateKeyPair(keySize);
                                BigInteger plaintext = decrypt(cip, privkey, modn);
                                String ptext = String.valueOf(plaintext);

                                runOnUiThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        edinmess.setText(ptext);
                                        ciphertext1.setText(ciphertext);

                                    }
                                });


                            }//function to send message to BOB
                            else{

                                PrintWriter printWriter =  new PrintWriter(socket.getOutputStream());
                                int keySize = 1024;
                                RSAKeyPair keyPair = generateKeyPair(keySize);

                                BigInteger plaintext = new BigInteger(edoutmess.getText().toString());
                                BigInteger encrypted = encrypt(plaintext, keyPair.getPublicKey(), keyPair.getModulus());
                                String mod = String.valueOf(keyPair.getModulus()) ;
                                String ciphertext = String.valueOf(encrypted);
                                String phi = String.valueOf(keyPair.getphi());
                                String pubkey = String.valueOf(keyPair.getPublicKey());


                                printWriter.println(ciphertext);
                                printWriter.println(mod);
                                printWriter.println(phi);
                                printWriter.println(pubkey);

                                printWriter.flush();
                                socket.close();
                            }


                        }
                        catch (IOException e){
                            e.printStackTrace();
                        }

                    }
                }).start();//added


            }
        });

    }
    //Class to generate keypair
    static class RSAKeyPair {
        private BigInteger publicKey;
        private BigInteger privateKey;
        private BigInteger modulus;
        private BigInteger phi;

        public RSAKeyPair(BigInteger publicKey, BigInteger privateKey, BigInteger modulus, BigInteger phi) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
            this.modulus = modulus;
            this.phi = phi;
        }

        public BigInteger getPublicKey() {
            return publicKey;
        }

        public BigInteger getPrivateKey() {
            return privateKey;
        }

        public BigInteger getModulus() {
            return modulus;
        }
        public BigInteger getphi() {
            return phi;
        }
    }
    //function to generate keypair
    public static RSAKeyPair generateKeyPair(int keySize) {
        SecureRandom random = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(keySize / 2, random);
        BigInteger q = BigInteger.probablePrime(keySize / 2, random);
        BigInteger n = p.multiply(q);
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        BigInteger e1 = BigInteger.valueOf(65537); // Commonly used public exponent
        BigInteger e = selecte(phi);
        BigInteger d = e.modInverse(phi);
        return new RSAKeyPair(e, d, n,phi);

    }
    //function to encrypt data
    public static BigInteger encrypt(BigInteger plaintext, BigInteger publicKey, BigInteger modulus) {
        return plaintext.modPow(publicKey, modulus);
    }
    //function to decrypt data
    public static BigInteger decrypt(BigInteger ciphertext, BigInteger privateKey, BigInteger modulus) {
        return ciphertext.modPow(privateKey, modulus);
    }
    //function to find the greatest common divisor
    public static BigInteger GCD(BigInteger a, BigInteger b){
        String z ="0";
        BigInteger zero = new BigInteger(z);
        if(b.equals(z)){
            return a;
        }
        return GCD(b,a.mod(b));
    }
    //function to find if two numbers are relatively prime
    public static boolean Is_Realtively_Prime(BigInteger a, BigInteger b){
        String o = "1";
        BigInteger o1 = new BigInteger(o);
        if(GCD(a, b).equals(o1)){
            return true;
        }
        return false;
    }
    //function to select e for the public key
    public static BigInteger selecte(BigInteger totient){
        SecureRandom random = new SecureRandom();
        BigInteger z = new BigInteger("1");
        BigInteger e;
        boolean t =false;

        do {
            e = BigInteger.probablePrime(1024 / 2, random);
            if(e.compareTo(z)>0 && e.compareTo(totient)<1){
                t=true;
            }

        }while(!t && !Is_Realtively_Prime(e,totient));
        return e;
    }

}