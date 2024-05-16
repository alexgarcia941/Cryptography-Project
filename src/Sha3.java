import java.util.Arrays;

/**
 * This is a class that serves as a library for the SHA-3 hash function derivatives
 * Complete: KMACXOF256
 * @author Alex Garcia
 */
public class Sha3 {

    //right_encode(0) output
    public static final byte[] RIGHT_ENCODE_0= {0x0,0x1};

    /**
     * KMACXOF256 hash function as described from NIST SP 800-185
     * Note: while there is a bug in cshake, it does not affect kmaxof output(tested with test vectors)
     * ref/insipration:
     *      provided implementation of KMACXOF256 by instructor.
     * @param key key string of any length
     * @param msg message to be hashed
     * @param length  requested output bits
     * @param cstm  customization string
     */
    public static byte[] KMACXOF256(byte[] key, byte[] msg, int length, byte[] cstm){//length in bits
        if (length % 8 != 0){
            throw new RuntimeException("length is not a multiple of 8!!!");
        }

        //init the sponge
        Sponge k = new Sponge();

        // N(function name) will always be "KMAC" here
        // ref NIST sp 800-185 definition 3.3
        // set up bytepad(encode_string(N) || encode_string(S), 136)
        byte[] nEncoded = encodeString("KMAC".getBytes());
        byte[] sEncoded = encodeString(cstm);
        byte[] concatNS = Arrays.copyOf(nEncoded, nEncoded.length + sEncoded.length);
        System.arraycopy(sEncoded, 0, concatNS, nEncoded.length, sEncoded.length);
        concatNS = bytepad(concatNS, Sponge.RSIZE);// bytepad(encode_string(N) || encode_string(S), 136)

        //now we can get into keccack[512]
        //k.spongeAbsorb(concatNS);

        //bytepad(encode_string(K), 136) from def 3.3
        byte[] formattedKey = bytepad(encodeString(key), Sponge.RSIZE);
        //k.spongeAbsorb(formattedKey);

        //prep message
        byte[] formattedMsg = Arrays.copyOf(msg, msg.length + RIGHT_ENCODE_0.length + 1);
        System.arraycopy(RIGHT_ENCODE_0, 0, formattedMsg, msg.length, RIGHT_ENCODE_0.length);
        formattedMsg[formattedMsg.length - 1] = (byte) 0x04;
        //k.spongeAbsorb(formattedMsg);

        //absorb phase(replicate the concating of these elements)
        //def 3.3 cshake 256 step 2
        k.spongeAbsorb(concatNS);
        k.spongeAbsorb(formattedKey);
        k.spongeAbsorb(formattedMsg);

        //squeeze output
        byte[] output = new byte[length/8];
        k.spongeSqueeze(output);
        return output;
    }


    /**
     * cShake256 hash function as described from NIST SP 800-185
     * ref/insipration:
     *      provided implementation of KMACXOF256 by instructor.
     * @param msg message to be hashed
     * @param length  requested output bits
     * @param funcName N- function-name string used to define functions
     * @param cstm  customization string
     */
    public static byte[] cShake256(byte[] msg, int length, byte[] funcName, byte[] cstm) {//length in bits{
        //initialize sponge(and state)
        Sponge k = new Sponge();
        k.cshakexof = true;

        // ref NIST sp 800-185 definition 3.3
        // set up bytepad(encode_string(N) || encode_string(S), 136)
        byte[] funcNameEnc = encodeString(funcName);

        byte[] sEncoded = encodeString(cstm);

        byte[] concatNS = Arrays.copyOf(funcNameEnc, funcNameEnc.length + sEncoded.length);
        System.arraycopy(sEncoded, 0, concatNS, funcNameEnc.length, sEncoded.length);
        concatNS = bytepad(concatNS, Sponge.RSIZE);// bytepad(encode_string(N) || encode_string(S), 136)

        //replicates bytepad(encode_string(N) || encode_string(S), 136) || X |
        k.spongeAbsorb(concatNS);
        k.spongeAbsorb(msg);

        //switch to squeezing output
        byte[] output = new byte[length/8];
        k.spongeSqueeze(output);
        return output;
    }

    /**
     * encodes the integer x as a byte string in a way that can be unambiguously parsed from the end of the string by
     * inserting the length of the byte string after the byte string representation of x.
     * @param x
     */
    private static void right_encode(int x){
        //similar logic to left encode
        //only the return value for 0 is needed so this is left as
        // a placeholder for possible future additions
    }

    /**
     * NIST doc:Encodes integer x encodes the integer x as a byte string in a way that can be unambiguously parsed from the
     * beginning of the string by inserting the length of the byte string before the byte string representation of x.
     * @param x integer to be encoded
     * references/Inspiration:
     *          NIST SP 800-185
     *          Article: https://cryptologie.net/article/388/shake-cshake-and-some-more-bit-ordering/
     *          Article golang implementation: https://gist.github.com/mimoo/7e815318e54d5c07c3330149ddf439c5
     * @return
     */
    private static byte[] left_encode(int x){
        // validity conditions: 0<= x <2^{2040}
        assert x>=0;
        //edge case
        if(x == 0){
            return new byte[]{(byte)1, (byte)0};
        }

        byte[] buffer = new byte[5];//using int so 4+1 bytes needed at most
        int n = 0;
        //fill buffer from end to start
        for (int i = 4; i > 0; i--){
            buffer[i] = (byte) (x & 0xFF);
            x >>>= 8;//unsigned shift
            n++;
            if (x==0) { break; }//stop once all zeros
        }

        buffer[4 - n] = (byte)n;

        byte[] res = new byte[n+1];//max of 5 in this specific case

        System.arraycopy(buffer, 4 - n, res, 0, n + 1 );
        return res;
    }

    /**
     * Encode bit strings in a way that may be parsed unambigously from the beginning of the string S.
     * as defined in NIST SP 800-185
     * @param S byte string to be encoded
     * @return
     */
    private static byte[] encodeString(byte[] S){
        byte[] senc = left_encode(S.length*8);//need to convert to bits
        byte[] result = new byte[senc.length + S.length];
        System.arraycopy(senc, 0, result, 0, senc.length);
        System.arraycopy(S, 0, result, senc.length, S.length);
        return result;
    }

    /**
     * Apply the NIST bytepad primitive to a byte array X with encoding factor w.
     * @param X the byte array to bytepad
     * @param w the encoding factor (the output length must be a multiple of w)
     * @return the byte-padded byte array X with encoding factor w.
     * reference:
     *          -provided bytepad method from instructor
     */
    private static byte[] bytepad(byte[] X, int w) {
        assert w > 0;

        //step 1:
        byte[] wenc = left_encode(w);
        byte[] z = new byte[w*((wenc.length + X.length + w - 1)/w)];

        // NB: z.length is the smallest multiple of w that fits wenc.length + X.length
        System.arraycopy(wenc, 0, z, 0, wenc.length);
        System.arraycopy(X, 0, z, wenc.length, X.length);

        // 2. (nothing to do: len(z) mod 8 = 0 in this byte-oriented implementation)
        // 3. while (len(z)/8) mod w ≠ 0: z = z || 00000000
        for (int i = wenc.length + X.length; i < z.length; i++) {
            z[i] = (byte)0;
        }
        // 4. return z
        return z;
    }

    /**
     * Return the substring of X from [a,b).
     * Note: not used in this project currently
     * @param X bit string
     * @param a start index
     * @param b end index
     * @return substring of X from [a,b).
     */
    private static byte[] substring(byte[] X, int a, int b) {
        if (a >= b || a > X.length) {
            return new byte[]{};
        }else if (b <= X.length){
            return Arrays.copyOfRange(X, a, b);
        }else{
            return Arrays.copyOfRange(X, a, X.length-1);
        }
    }
}
