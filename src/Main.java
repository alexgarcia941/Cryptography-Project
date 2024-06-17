/**
 * Driver Class for program, provides functionality for all 6 services(4 required and 2 extra-credit)
 * @author Alex Garcia
 */
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;


public class Main {

    /**
     * Entry point to the program
     * @param args
     */
    public static void main(String[] args) {
       //print command-line options if no options provided
        if (args.length == 0) {
            printOptions();
            return;
        }

       //retrieve the flag
        String flag = args[0];

            switch (flag) {
                case "-hf":
                    if (args.length != 3) {
                        throw new IllegalArgumentException("Usage: java Main -hf <input-file> <out-file>");
                    }
                    plainHash(args[1], args[2], true);
                    break;
                case "-ht":
                    if (args.length != 3) {
                        throw new IllegalArgumentException("Usage: java Main -ht <input-text> <out-file>");
                    }
                    plainHash(args[1], args[2], false);
                    break;
                case "-macf":
                    if (args.length != 4) {
                        throw new IllegalArgumentException("Usage: java Main -macf <input-file> <pw-src-file> <out-file>");
                    }
                    genMacTag(args[1], args[2], args[3], true);
                    break;
                case "-mact":
                    if (args.length != 4) {
                        throw new IllegalArgumentException("Usage: java Main -mact <input-text> <pw-text> <out-file>");
                    }
                    genMacTag(args[1], args[2], args[3], false);
                    break;
                case "-enc":
                    if (args.length != 4) {
                        throw new IllegalArgumentException("Usage: java Main -enc <input-file> <pw-src-file> <out-file>");
                    }
                    symmCrypt(args[1], args[2], args[3]);
                    break;
                case "-dec":
                    if (args.length != 3) {
                        throw new IllegalArgumentException("Usage: java Main -dec <input-file> <pw-src-file>");
                    }
                    decryptFile(args[1], args[2]);
                    break;

                case "-ekp":
                    if (args.length != 3) {
                        throw new IllegalArgumentException("Usage: java Main -ekp <pw-src-file> <output-file>");
                    }
                    genElipticKeyPair(args[1], args[2]);
                    break;

                case"-elenc":
                    if (args.length != 4) {
                        throw new IllegalArgumentException("Usage: java Main -elenc <input-file> <public-key-src> <output-file>");
                    }
                    elipticEncrypt(args[1], args[2], args[3]);
                    break;
                case"-eldec":
                    if (args.length != 3) {
                        throw new IllegalArgumentException("Usage: java Main -eldec <pw-file> <cryptogram-file>");
                    }
                    elipticDecrypt( args[1], args[2]);
                    break;
                case"-s":
                    if (args.length != 4) {
                        throw new IllegalArgumentException("Usage: java Main -s <input-file> <pw-file> <output-file>");
                    }
                    signFile(args[1], args[2], args[3]);
                    break;
                case"-vs":
                    if (args.length != 4) {
                        throw new IllegalArgumentException("Usage: java Main -vs <signature-file> <input-file> <public-key-file>");
                    }
                    verifySigniture(args[1], args[2], args[3]);
                    break;
                default:
                    System.out.println("Error: Invalid command.");
                    printOptions();
                    break;
            }
    }

    /**
     * Completes service 1 and 1st bonus:
     * h <= KMACXOF256(“”, m, 512, “D”)
     * @param input input file name
     * @param outDir output file name
     * @param isFile boolean input is a file
     */
    private static void plainHash(String input, String outDir, boolean isFile) {
        byte[] msg;

        // read in input
       if (isFile){
           File file = new File(input);
           msg = new byte[(int) file.length()];
           try{
               FileInputStream fis = new FileInputStream(file);
               fis.read(msg);
               fis.close();
           } catch (FileNotFoundException e) {
               throw new RuntimeException(e);
           } catch (IOException e) {
               throw new RuntimeException(e);
           }
       }else{
           //read directly from command line
           msg  = input.getBytes();
       }

       //generate hash
       byte[] out = Sha3.KMACXOF256("".getBytes(), msg, 512, "D".getBytes());

       //write to output
       String outHex = byteToHex(out);
        try (FileWriter writer = new FileWriter(outDir, false)) {
            writer.write(outHex);
            writer.close();
            System.out.println("Successfully wrote to the output file.");
        } catch (IOException e) {
            System.out.println("An error occurred while writing to the output file");
        }
    }


    /**
     * Completes Service2:
     * t <= KMACXOF256(pw, m, 512, “T”)
     * @param inputFile input file name
     * @param pwFile file name with passphrase in it
     * @param outDir output file name
     * @param isFile
     */
    private static void genMacTag(String inputFile, String pwFile, String outDir, boolean isFile) {
        byte[] msg;
        byte[] pw;

        //collect input
        if (isFile){
            File file = new File(inputFile);
            File keyFile = new File(pwFile);
            msg = new byte[(int) file.length()];
            pw = new byte[(int) keyFile.length()];
            try {
                FileInputStream fis = new FileInputStream(file);
                fis.read(msg);
                fis.close();

                FileInputStream pwis = new FileInputStream(keyFile);
                pwis.read(pw);
                pwis.close();
            } catch (FileNotFoundException e) {
                throw new RuntimeException(e);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }else{
            msg  = inputFile.getBytes();
            pw = pwFile.getBytes();
        }

        //generate hash
        byte[] out = Sha3.KMACXOF256(pw, msg, 512, "T".getBytes());

        //write to output
        String outHex = byteToHex(out);
        try (FileWriter writer = new FileWriter(outDir, false)) {
            writer.write(outHex);
            writer.close();
            System.out.println("Successfully wrote to the output file.");
        } catch (IOException e) {
            System.out.println("An error occurred while writing to the output file");
        }
    }

    /**
     * Completes Service 3:
     * Encrypt a given data file symmetrically under a given passphrase.
     * @param inputFile
     * @param pwFile
     * @param outDir
     */
    private static void symmCrypt(String inputFile, String pwFile, String outDir) {
        SecureRandom random = new SecureRandom();
        byte[] z = new byte[64];//512 bytes
        random.nextBytes(z);

        //gather input(key and msg)
        byte[] msg;
        byte[] pw;

        File file = new File(inputFile);
        File keyFile = new File(pwFile);
        msg = new byte[(int) file.length()];
        pw = new byte[(int) keyFile.length()];
        try {
            FileInputStream fis = new FileInputStream(file);
            fis.read(msg);
            fis.close();
            FileInputStream pwis = new FileInputStream(keyFile);
            pwis.read(pw);
            pwis.close();
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        //key = z||pw
        byte[] key = new byte[z.length + pw.length];
        System.arraycopy(z,0,key, 0, z.length);
        System.arraycopy(pw, 0, key,z.length, pw.length );

        //generate keka and split
        byte[] keka = Sha3.KMACXOF256(key, "".getBytes(), 1024, "S".getBytes());
        byte[] ke = new byte[keka.length/2];//512bits(64bytes)
        byte[] ka = new byte[keka.length/2];
        System.arraycopy(keka, 0, ke, 0, keka.length/2);
        System.arraycopy(keka, ka.length, ka, 0, keka.length/2);

        //generate c
        byte[] c = Sha3.KMACXOF256(ke, "".getBytes(), msg.length*8, "SKE".getBytes());
        for(int i = 0; i<msg.length; i++ ){
            c[i] ^= msg[i];
        }

        //generate t
        byte[] t = Sha3.KMACXOF256(ka, msg, 512, "SKA".getBytes());


        //write symmetric cryptogram to file

        //write to output
        String zHex = byteToHex(z);
        String cHex = byteToHex(c);
        String tHex = byteToHex(t);
        String cryptogram = zHex + "," + cHex + "," + tHex;

        try (FileWriter writer = new FileWriter(outDir, false)) {
            writer.write(cryptogram);
            writer.close();
            System.out.println("Successfully wrote to the file.");
        } catch (IOException e) {
            System.out.println("An error occurred while writing to the output file");
        }

    }

    /**
     * Completes Service 4:
     * Decrypt a given symmetric cryptogram under a given passphrase.
     * @param inputFile
     * @param pwSrc
     */
    private static void decryptFile(String inputFile, String pwSrc) {
       byte[] z = new byte[64];
       byte[] c, t;
       byte[] symCryptBytes;
       byte[] pw;

        try {
            //read in symmetric cryptogram
            File inFile = new File(inputFile);
            symCryptBytes = new byte[(int) inFile.length()];
            FileInputStream fis = new FileInputStream(inFile);
            fis.read(symCryptBytes);
            fis.close();

            //read in key/pw
            File pwFile = new File(pwSrc);
            pw = new byte[(int) pwFile.length()];
            FileInputStream pwis = new FileInputStream(pwSrc);
            pwis.read(pw);
            pwis.close();
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        String symCryptString = new String(symCryptBytes, StandardCharsets.UTF_8);
        String[] zct = symCryptString.split(",");

        if(zct.length != 3){
            throw new RuntimeException("Error with Input");
        }
        z = HexFormat.of().parseHex(zct[0]);
        c = HexFormat.of().parseHex(zct[1]);
        t = HexFormat.of().parseHex(zct[2]);

        //key = z||pw
        byte[] key = new byte[z.length + pw.length];
        System.arraycopy(z,0,key, 0, z.length);
        System.arraycopy(pw, 0, key,z.length, pw.length );

        //generate keka and split
        byte[] keka = Sha3.KMACXOF256(key, "".getBytes(), 1024, "S".getBytes());
        byte[] ke = new byte[keka.length/2];//512bits(64bytes)
        byte[] ka = new byte[keka.length/2];
        System.arraycopy(keka, 0, ke, 0, keka.length/2);
        System.arraycopy(keka, ka.length, ka, 0, keka.length/2);


        byte[] msg = Sha3.KMACXOF256(ke, "".getBytes(), c.length*8, "SKE".getBytes());
        for(int i = 0; i<msg.length; i++ ){
            msg[i] ^= c[i];
        }

        byte[] nt = Sha3.KMACXOF256(ka, msg, 512, "SKA".getBytes());

        boolean accept = Arrays.equals(nt, t);
        if (accept){
            System.out.println("Accepted");
        }else{
            System.out.println("Rejected");
        }
    }

    private static void printOptions() {
        String usage = "Usage:\n"+
                " java Main -hf <input-file> <out-file>  " +
                "| Compute a plain cryptographic hash of a given file\n"+
                " java Main -ht <input-text> <out-file>  "+
                "| Compute a plain cryptographic hash of text input.\n"+
                " java Main -macf <input-file> <pw-src-file> <out-file>  " +
                "| Compute an authentication tag (MAC) of a given file under a given passphrase.\n"+
                " java Main -mact <input-text> <pw-text> <out-file>  "+
                "| Compute an authentication tag (MAC) of text input under a given passphrase(pw)\n"+
                " java Main -enc <input-file> <pw-src-file> <out-file>  "+
                "| Encrypt a given data file symmetrically under a given passphrase. Output is format z,c,t\n"+
                " java Main -dec <input-file> <pw-src-file>"+
                "| Decrypt a given symmetric cryptogram(input) under a given passphrase. input must be in form z,c,t\n"+
                "java Main -ekp <pw-src-file> <output-file>"+
                "| Generate an elliptic key pair s,V from a given passphrase and write public key to file in form Vx,Vy.\n"+
                "java Main -elenc <input-file> <public-key-src> <output-file>"+
                "| Encrypt a data file under a given elliptic public key file and write the ciphertext to a file.\n"+
                "java Main -eldec <pw-file> <cryptogram-file>"+
                "| Decrypt a given elliptic-encrypted file from a given password and write the decrypted data to a file.\n"+
                "java Main -s <input-file> <pw-file> <output-file>"+
                "| Sign a given file from a given password and write the signature to a file.\n"+
                "java Main -vs <signature-file> <input-file> <public-key-file>"+
                "| Verify a given data file and its signature file under a given public key file\n";
        System.out.println(usage);
    }

    /**
     * Generate an elliptic key pair from a given passphrase and write the public key to a file.
     * @param pwSrc given passphrase
     * @param publicDir directory for the public key file
     */
    public static void genElipticKeyPair(String pwSrc, String publicDir){
        //read in pw
        byte[] pw;
        try {

            //read in key/pw
            File pwFile = new File(pwSrc);
            pw = new byte[(int) pwFile.length()];
            FileInputStream pwis = new FileInputStream(pwSrc);
            pwis.read(pw);
            pwis.close();
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        byte[] sBytes = Sha3.KMACXOF256(pw, "".getBytes(), 448, "SK".getBytes());
        BigInteger s = new BigInteger(sBytes);
        s = s.multiply(BigInteger.valueOf(4)).mod(ED448.r);
        ED448 G = ED448.ed448gen(false);
        ED448 V = G.scalMul(s);
        try (FileWriter writer = new FileWriter(publicDir, false)) {
            writer.write(V.getX().toString());
            writer.write(",");
            writer.write(V.getY().toString());
            writer.close();
            System.out.println("Successfully public key to the file.");
        } catch (IOException e) {
            System.out.println("An error occurred while writing to the output file");
        }
    }

    /**
     * Encrypt a data file under a given elliptic public key file and write
     * the ciphertext to a file.
     * @param inputFile data file to be encrypted
     * @param publicKeyFile file containing public key
     * @param outDir file to write output to
     */
    public static void elipticEncrypt(String inputFile, String publicKeyFile, String outDir){
        //read in given file and public key V
        File file = new File(inputFile);
        File keyFile = new File(publicKeyFile);
        byte[] msg = new byte[(int) file.length()];
        byte[] v_bytes  = new byte[(int) keyFile.length()];

        try {
            FileInputStream fis = new FileInputStream(file);
            fis.read(msg);
            fis.close();
            FileInputStream vInputStream = new FileInputStream(keyFile);
            vInputStream.read(v_bytes);
            vInputStream.close();
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        String publicKeyString = new String(v_bytes, StandardCharsets.UTF_8);
        String[] vXY = publicKeyString.split(",");

        if(vXY.length != 2){
            throw new RuntimeException("Error with Public key");
        }
        BigInteger x = new BigInteger(vXY[0]);
        BigInteger y = new BigInteger(vXY[1]);
        ED448 V = new ED448(x, y);

        //k <- Random(448);
        SecureRandom random = new SecureRandom();
        byte[] k_bytes = new byte[56];//512 bytes
        random.nextBytes(k_bytes);
        BigInteger k = new BigInteger(k_bytes);

        //k <- 4k (mod r)
        k = k.multiply(BigInteger.valueOf(4)).mod(ED448.r);

        //W <- k*V; Z <- k*G
        ED448 G = ED448.ed448gen(false);
        ED448 W = V.scalMul(k);
        ED448 Z = G.scalMul(k);

        //generate keka and split
        //(ka || ke) <- KMACXOF256(Wx, "", 2×448, “PK”)
        byte[] keka = Sha3.KMACXOF256(W.getX().toByteArray(), "".getBytes(), 2*448, "PK".getBytes());
        byte[] ke = new byte[keka.length/2];//448bits(56bytes)
        byte[] ka = new byte[keka.length/2];
        System.arraycopy(keka, 0, ke, 0, keka.length/2);
        System.arraycopy(keka, ka.length, ka, 0, keka.length/2);

        //c <- KMACXOF256(ke, "", |m|, “PKE”) Xor m
        byte[] c = Sha3.KMACXOF256(ke, "".getBytes(), msg.length * 8, "PKE".getBytes());
        for(int i = 0; i<msg.length; i++ ){
            c[i] ^= msg[i];
        }

        byte[] t = Sha3.KMACXOF256(ka, msg, 448, "PKA".getBytes());


        String zXString = Z.getX().toString();
        String zYString = Z.getY().toString();
        String cHex = byteToHex(c);
        String tHex = byteToHex(t);

        String cryptogram = zXString + "," +zYString + "," + cHex + "," + tHex;

        try (FileWriter writer = new FileWriter(outDir, false)) {
            writer.write(cryptogram);
            writer.close();
            System.out.println("Successfully wrote to the file.");
        } catch (IOException e) {
            System.out.println("An error occurred while writing to the output file");
        }
    }

    /**
     * Decrypt a given elliptic-encrypted file from a given password and
     * write the decrypted data to a file.
     * @param pwSrc filename of file containing passphrase
     * @param cryptogramFile filename of file containing cryptogram
     */
    public static void elipticDecrypt(String pwSrc, String cryptogramFile){
        //read in passphrase and cryptogram
        byte[] c, t;
        byte[] CryptBytes;
        byte[] pw;

        try {
            //read in symmetric cryptogram
            File inFile = new File(cryptogramFile);
            CryptBytes = new byte[(int) inFile.length()];
            FileInputStream fis = new FileInputStream(inFile);
            fis.read(CryptBytes);
            fis.close();

            //read in key/pw
            File pwFile = new File(pwSrc);
            pw = new byte[(int) pwFile.length()];
            FileInputStream pwis = new FileInputStream(pwSrc);
            pwis.read(pw);
            pwis.close();
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        String symCryptString = new String(CryptBytes, StandardCharsets.UTF_8);
        String[] zct = symCryptString.split(",");

        if(zct.length != 4){
            throw new RuntimeException("Error with Input");
        }

        BigInteger zX = new BigInteger(zct[0]);
        BigInteger zY = new BigInteger(zct[1]);
        c = HexFormat.of().parseHex(zct[2]);
        t = HexFormat.of().parseHex(zct[3]);
        ED448 Z = new ED448( zX, zY);

        byte[] s_bytes = Sha3.KMACXOF256(pw, "".getBytes(), 448, "SK".getBytes());
        BigInteger s = new BigInteger(s_bytes);
        s = s.multiply(BigInteger.valueOf(4)).mod(ED448.r);

        ED448 W = Z.scalMul(s);

        //generate keka and split
        //(ka || ke) <- KMACXOF256(Wx, "", 2×448, “PK”)
        byte[] keka = Sha3.KMACXOF256(W.getX().toByteArray(), "".getBytes(), 2*448, "PK".getBytes());
        byte[] ke = new byte[keka.length/2];//448bits(56bytes)
        byte[] ka = new byte[keka.length/2];
        System.arraycopy(keka, 0, ke, 0, keka.length/2);
        System.arraycopy(keka, ka.length, ka, 0, keka.length/2);

        //m <- KMACXOF256(ke, "", |m|, “PKE”) Xor c
        byte[] msg = Sha3.KMACXOF256(ke, "".getBytes(), c.length * 8, "PKE".getBytes());
        for(int i = 0; i<msg.length; i++ ){
            msg[i] ^= c[i];
        }

        byte[] nt = Sha3.KMACXOF256(ka, msg, 448, "PKA".getBytes());

        boolean accept = Arrays.equals(nt, t);
        if (accept){
            System.out.println("Accepted");
        }else{
            System.out.println("Rejected");
        }
    }

    /**
     * Sign a given file from a given password and write the signature to
     * a file
     * @param msgFile filename of file to be signed
     * @param pwSrc filename of file containing passphrase
     * @param outDir file to write output to
     */
    public static void signFile(String msgFile, String pwSrc, String outDir){
        //gather input(key and msg)
        byte[] msg;
        byte[] pw;

        File file = new File(msgFile);
        File keyFile = new File(pwSrc);
        msg = new byte[(int) file.length()];
        pw = new byte[(int) keyFile.length()];
        try {
            FileInputStream fis = new FileInputStream(file);
            fis.read(msg);
            fis.close();
            FileInputStream pwis = new FileInputStream(keyFile);
            pwis.read(pw);
            pwis.close();
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        byte[] sBytes = Sha3.KMACXOF256(pw, "".getBytes(), 448, "SK".getBytes());
        BigInteger s = new BigInteger(sBytes);
        s = s.multiply(BigInteger.valueOf(4)).mod(ED448.r);

        byte[] kBytes = Sha3.KMACXOF256(s.toByteArray(), msg, 448, "N".getBytes());
        BigInteger k = new BigInteger(kBytes);
        k = k.multiply(BigInteger.valueOf(4)).mod(ED448.r);

        ED448 G = ED448.ed448gen(false);
        ED448 U = G.scalMul(k);

        byte[] hBytes = Sha3.KMACXOF256(U.getX().toByteArray(), msg, 448, "T".getBytes());
        BigInteger h = new BigInteger(hBytes);

        BigInteger z = k.subtract(h.multiply(s)).mod(ED448.r);

        String hHex = byteToHex(h.toByteArray());
        String zHex = byteToHex(z.toByteArray());

        String signature = hHex + "," + zHex;
        try (FileWriter writer = new FileWriter(outDir, false)) {
            writer.write(signature);
            writer.close();
            System.out.println("Successfully wrote to the file.");
        } catch (IOException e) {
            System.out.println("An error occurred while writing to the output file");
        }
    }

    /**
     * Verify a given data file and its signature file under a given public
     * key file.
     * @param signSrc file containing signature (h,z)
     * @param msgFile file containing msg to verify
     * @param publicKeySrc file containing public key
     */
    public static void verifySigniture(String signSrc, String msgFile, String publicKeySrc){
        //read in given sign, msg, and publicKey
        byte[] hBytes, zBytes, signBytes, msg, publicKeyBytes;
        BigInteger h, z;
        ED448 V;

        try {
            //read in signature
            File inFile = new File(signSrc);
            signBytes = new byte[(int) inFile.length()];
            FileInputStream fis = new FileInputStream(inFile);
            fis.read(signBytes);
            fis.close();

            //read in msg file
            File mFile = new File(msgFile);
            msg = new byte[(int) mFile.length()];
            FileInputStream mis = new FileInputStream(msgFile);
            mis.read(msg);
            mis.close();

            //read in public key
            File pubFile = new File(publicKeySrc);
            publicKeyBytes= new byte[(int) pubFile.length()];
            FileInputStream pubIs = new FileInputStream(pubFile);
            pubIs.read(publicKeyBytes);
            pubIs.close();
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        //extract signature
        String symCryptString = new String(signBytes, StandardCharsets.UTF_8);
        String[] hz = symCryptString.split(",");

        if(hz.length != 2){
            throw new RuntimeException("Error with Input");
        }
        hBytes = HexFormat.of().parseHex(hz[0]);
        zBytes = HexFormat.of().parseHex(hz[1]);

        h = new BigInteger(hBytes);
        z = new BigInteger(zBytes);

        //extract public key
        String publicKeyString = new String(publicKeyBytes, StandardCharsets.UTF_8);
        String[] vXY = publicKeyString.split(",");

        if(vXY.length != 2){
            throw new RuntimeException("Error with Public key");
        }
        BigInteger x = new BigInteger(vXY[0]);
        BigInteger y = new BigInteger(vXY[1]);
        V = new ED448(x, y);

        ED448 G = ED448.ed448gen(false);

        ED448 U = G.scalMul(z).add(V.scalMul(h));

        byte[] nh = Sha3.KMACXOF256(U.getX().toByteArray(), msg, 448, "T".getBytes());

        boolean accept = Arrays.equals(nh, h.toByteArray());
        if (accept){
            System.out.println("Accepted");
        }else{
            System.out.println("Rejected");
        }
    }

    /**
     * utility function to get hex string from byte array
     * @param bytes bytes to convert
     * @return
     * references:
     *          https://www.geeksforgeeks.org/java-program-to-convert-byte-array-to-hex-string/
     */
    public static String byteToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder(3 * bytes.length);
        for (int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(0xFF & bytes[i]);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString().toUpperCase();
    }


}