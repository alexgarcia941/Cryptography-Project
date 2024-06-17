import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * This class is simply used for testing, might not be included in the final result
 * @author Alex Garcia
 */

public class Test {
    public static void main(String[] args){

//        //CSHAKE256()
//        sample3();
//        cShakeSample4();
//
//        //KMACXOF256()
//        sample4();
//        sample5();
//        sample6();
        //testElicpticCurve();
        randomTestElipticCurve();
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

    public static void testElicpticCurve(){

        //testiing the neutral points
        ED448 O = new ED448();
        ED448 O_3 = new ED448(BigInteger.ONE, false);
        System.out.println("Testing netral point");
        System.out.println(O.equals(O_3));
        System.out.println("Testing netral point");

        ED448 G = ED448.ed448gen(false);
        System.out.println("Testing netral point");

        ED448 G1 = G.scalMul(BigInteger.ZERO);
        System.out.println("0 ⋅ G = O: " + G1.equals(O));

        ED448 G2 = G.scalMul(BigInteger.ONE);
        System.out.println("1 ⋅ G = G: " + G2.equals(G));

        ED448 gNeg = G.inverse();
        ED448 G3 = G.add(gNeg);
        System.out.println("G + (-G) = O: " + G3.equals(O));

        ED448 G4 = G.scalMul(BigInteger.TWO);
        System.out.println("2G = G + G: " + G4.equals(G.add(G)));

        ED448 G5 = G.scalMul(BigInteger.valueOf(4));
        ED448 G6 = G.scalMul(BigInteger.TWO).scalMul(BigInteger.TWO);
        System.out.println("4G = 2*(2*G): " + G5.equals(G6));

        System.out.println("4G = O: " + G5.equals(O));

        ED448 RG = G.scalMul(ED448.r);

        System.out.println("rG = O: " + RG.equals(O));

    }

    public static void randomTestElipticCurve(){
        SecureRandom random = new SecureRandom();
        BigInteger[] bigIntegers = new BigInteger[3];
        ED448 G = ED448.ed448gen(false);

        //for loop to repeat tests
        for(int i = 0; i<1000; i++) {
            System.out.println("test"+i);
            // Generate 3 random BigIntegers with a maximum bit length of 448
            for (int j = 0; j < 3; j++) {
                bigIntegers[j] = new BigInteger(448, random);
            }
            BigInteger k = bigIntegers[0];
            BigInteger l = bigIntegers[1];
            BigInteger m = bigIntegers[2];

            //test 1
            ED448 left1 = G.scalMul(k);
            ED448 right1 = G.scalMul(k.mod(ED448.r));

            boolean test1 = left1.equals(right1);
            if(!test1){
                throw new AssertionError("failed test1");
            }
            //test2
            ED448 left2 = G.scalMul(k.add(BigInteger.ONE));
            ED448 right2 = G.add(G.scalMul(k));
            boolean test2 = left2.equals(right2);
            if(!test2){
                throw new AssertionError("failed test2");
            }

            //test3
            ED448 left3 = G.scalMul(k.add(l));
            ED448 right3 = G.scalMul(k).add(G.scalMul(l));
            boolean test3 = left3.equals(right3);
            if(!test3){
                throw new AssertionError("failed test3");
            }

            //test4
            ED448 left4 = G.scalMul(l).scalMul(k);
            ED448 middle4 = G.scalMul(k).scalMul(l);
            ED448 right4 = G.scalMul(k.multiply(l).mod(ED448.r));
            boolean test4 = left4.equals(middle4) && middle4.equals(right4);
            if(!test4){
                throw new AssertionError("failed test4");
            }

            //test5
            ED448 left5 = G.scalMul(k).add(G.scalMul(l).add(G.scalMul(m)));
            ED448 right5 = G.scalMul(m).add(G.scalMul(k).add(G.scalMul(l)));
            boolean test5 = left5.equals(right5);
            if(!test5){
                System.out.println("failed ");
                throw new AssertionError("failed test5");
            }

        }
    }
}
