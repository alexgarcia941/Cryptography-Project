/**
 * This class holds the keccak[512] core algorithim and sponge functionalities
 * @author Alex Garcia
 */


public class Sponge {
    //used for cshake to work(for testing, set to false for kmacxof)
    public boolean cshakexof = false;

    //rate size in bytes
    public static final int RSIZE = 136;
    private static final int NUMBEROFROUNDS = 24;
    //round constants from tiny sha.3
    private static final long[] KECCAKF_RNDC = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
            0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
            0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
            0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
            0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
            0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
            0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };
    private static final int[] KECCAKF_ROTC = {
            1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
            27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
    };
    private static final int[] KECCAKF_PILN = {
            10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
            15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
    };
    //pointer as used in tiny.sha3
    private  int pt;

    private byte[] state;

    public Sponge(){
        this.state = new byte[200];
        this.pt = 0;
    }

    /**
     * Applies the keccak permutations to a 1600b-wide (200/25 byte/long) state
     *the current state to apply the permutations on
     * @param state
     * references/inspiration:
     *              Tiny sha-3 provided by instructor
     */
    private static void keccakF1600(byte[] state) {
        long[] stateLanes = new long[25];

        //big endianess converstion(should be redundant on little-endainess) into an array of longs
        for (int i = 0; i < stateLanes.length; i++){
           stateLanes[i] = (state[(8*i)] & 0xFF |
                   ((long) (state[(8 * i) + 1 ] & 0xFF) << 8) |
                   ((long) (state[(8 * i) + 2 ] & 0xFF) << 16) |
                   ((long) (state[(8 * i) + 3 ] & 0xFF) << 24) |
                   ((long) (state[(8 * i) + 4 ] & 0xFF) << 32) |
                   ((long) (state[(8 * i) + 5 ] & 0xFF) << 40) |
                   ((long) (state[(8 * i) + 6 ] & 0xFF) << 48) |
                   ((long) (state[(8 * i) + 7 ] & 0xFF) << 56) );
        }

        //variables;
        int i,j,r;
        long t;
        long[] bc = new long[5];

        // actual iteration(the 24 rounds, used to encode each segment of the original message)
        for ( r = 0; r < NUMBEROFROUNDS; r++) {
            // Theta
            for (i = 0; i < 5; i++) {
                bc[i] = stateLanes[i] ^ stateLanes[i + 5] ^ stateLanes[i + 10] ^ stateLanes[i + 15] ^ stateLanes[i + 20];
            }


            for ( i = 0; i < 5; i++) {
                t = bc[(i + 4) % 5] ^ ROTLEFT64(bc[(i + 1) % 5], 1);
                for ( j = 0; j < 25; j += 5) {
                    stateLanes[j + i] ^= t;
                }
            }

            // Rho Pi
            t = stateLanes[1];
            for ( i = 0; i < 24; i++) {
                j = KECCAKF_PILN[i];
                bc[0] = stateLanes[j];
                stateLanes[j] = ROTLEFT64(t, KECCAKF_ROTC[i]);
                t = bc[0];
            }

            //  Chi
            for (j = 0; j < 25; j += 5) {
                for (i = 0; i < 5; i++) {
                    bc[i] = stateLanes[j + i];
                }
                for (i = 0; i < 5; i++) {
                    stateLanes[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
                }
            }
            //  Iota
            stateLanes[0] ^= KECCAKF_RNDC[r];
        }

        // Convert lanes(longs) back to bytes and update state
        for (int currLane = 0; currLane < 25; currLane++) {
            long temp = stateLanes[currLane];
            for (int byteIndex = 0; byteIndex < 8; byteIndex++) {//each 8 bytes is 1 lane
                state[(8 * currLane) + byteIndex] = (byte) (temp >>> (8 * byteIndex));
            }
        }
    }


    /**
     * Absorbs r amount of data from the message(absorbtion phase of the sponge)
     * @param message the message chunk to be absorbed
     * references I used for insipiration(hybrid of the 3):
     *                 -https://github.com/XKCP/XKCP/blob/master/Standalone/CompactFIPS202/Python/CompactFIPS202.py
     *                 -tiny sha-3 example provided by professor
     *                 -drcapybara's golang implementation
     */
    public void spongeAbsorb(byte[] message){
        int j = pt;

        //pad message if needed
        byte[] P = message;
        if (message.length % RSIZE != 0){
            P = padTenOne(message);
        }

        //iterate message and xor rate number of bytes
        for (byte b : P){
            this.state[j] ^= b;
            j++;
            //run permutations and reset every rate number of bytes
            if(j>= RSIZE){
                keccakF1600(state);
                j=0;
            }
        }
        pt = j;
    }

    /**
     * squeezes out output bytes as described in FIPS 202
     * @param output output byte array
     */
    public  void spongeSqueeze(byte[] output){
        int j = pt;

        //same idea as abosrb just without xor of r bytes
        for (int i = 0; i < output.length; i++){
            //run permuations and reset pointer
            if(j>= RSIZE){
                keccakF1600(state);
                j=0;
            }
            output[i] = state[j]; // copy to output
            j++;
        }
        //store pointer value
        pt = j;
    }

    /**
     * pad10*1 BYTE implementation of specification from FIPS 202 Algorithim 9
     * pads m to be a multiple of the rate
     * @param m byte array to be padded
     * @return padded array that is a multiple of the rate
     * References/insipiration:
     *          -Xof example provided by insructor
     *          -drcapybara's golang implementation
     */
    private byte[] padTenOne(byte[] m){
        int j =  (RSIZE - (m.length % RSIZE)) ;
        byte[] result = new byte[m.length + j];
        System.arraycopy(m, 0, result, 0, m.length);
        if(this.cshakexof){
            result[m.length] = (byte)0x04;// for cshake
        }
        result[m.length+j-1] = (byte) 0x80;
        return result;
    }

    /**
     * Utility function to rotate x  by y mod 64 bits to the left
     * @param x bits to be shifted
     * @param k factor to shift by
     * @return x shifted left by k bits
     */
    private static long ROTLEFT64(long x, int k) {
        return Long.rotateLeft(x, k);
    }

}
