/**
 * This class is simply used for testing, might not be included in the final result
 * @author Alex Garcia
 */

public class Test {
    public static void main(String[] args){

        //CSHAKE256()
        sample3();
        cShakeSample4();

        //KMACXOF256()
        sample4();
        sample5();
        sample6();
    }

    /**
     * sample #4 for KMACXOF256()
     */
    public static void sample4(){

        byte[] key = {
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
                0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F
        };
        byte[] data = {0x00, 0x01, 0x02, 0x03};

        String S = "My Tagged Application";

        /*
        the result is:(tested and works)
        17 55 13 3F 15 34 75 2A AD 07 48 F2 C7 06 FB 5C 78 45 12 CA B8
        35 CD 15 67 6B 16 C0 C6 64 7F A9 6F AA 7A F6 34 A0 BF 8F F6 DF
        39 37 4F A0 0F AD 9A 39 E3 22 A7 C9 20 65 A6 4E B1 FB 08 01 EB 2B
         */

       byte[] res = Sha3.KMACXOF256(key, data, 512, S.getBytes());
       System.out.println("---Sample#4 Output----");
       System.out.println(Main.byteToHex(res));

    }

    public static void sample5(){
        byte[] key = {
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
                0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F
        };

        byte[] data = new byte[200];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i); // Filling the array with sequential values
       }

        String S = "";

        byte[] res = Sha3.KMACXOF256(key, data, 512, S.getBytes());
        System.out.println("---Sample#5 Output----");
        System.out.println(Main.byteToHex(res));
    }
    public static void sample6(){
        byte[] key = {
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
                0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F
        };

        byte[] data = new byte[200];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i); // Filling the array with sequential values
        }

        String S = "My Tagged Application";

        byte[] res = Sha3.KMACXOF256(key, data, 512, S.getBytes());
        System.out.println("---Sample#6 Output----");
        System.out.println(Main.byteToHex(res));
    }

    public static void sample3(){
        byte[] data = {0x00, 0x01, 0x02, 0x03};

        byte[] res = Sha3.cShake256(data, 512, "".getBytes(), "Email Signature".getBytes());
        System.out.println("---cShake Sample#3 Output----");
        System.out.println(Main.byteToHex(res));
    }
    public static void cShakeSample4(){
        byte[] data = new byte[200];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i); // Filling the array with sequential values
        }
        byte[] res = Sha3.cShake256(data, 512, "".getBytes(), "Email Signature".getBytes());
        System.out.println("---cShake Sample#4 Output----");
        System.out.println(Main.byteToHex(res));
    }
}
