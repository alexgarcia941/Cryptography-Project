/**
 * Driver Class for program, provides functionality for all 6 services(4 required and 2 extra-credit)
 * @author Alex Garcia
 */
import java.io.*;
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
                default:
                    System.out.println("Error: Invalid command.");
                    printOptions();
                    break;
            }
    }

    /**
     * Completes service 1 and 1st bonus:
     * h <= KMACXOF256(“”, m, 512, “D”)
     *
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
                "| Decrypt a given symmetric cryptogram(input) under a given passphrase. input must be in form z,c,t";
        System.out.println(usage);
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