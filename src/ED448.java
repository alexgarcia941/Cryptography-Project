import java.math.BigInteger;
/**
 *ED448 Ed448-Goldilocks curve (an Edwards Curve)
 * defined by prime number p and a curve equation
 * This class contains operations methods to perform arithmetic operations on the curve
 * Curve Equation: (x^2 + y^2) = 1 + dx^{2}y^{2} with d = -39081
 * @author Alex Garcia
 */

public class ED448 {

    // p:=2^{448}-2^{224}-1, a prime number defining finite field F_p
    private final static BigInteger p =
            BigInteger.ONE.shiftLeft(448).subtract(BigInteger.ONE.shiftLeft(224)).subtract(BigInteger.ONE);
    private final static BigInteger d = BigInteger.valueOf(39081).negate(); //d = -39081
    private BigInteger x; //x coordinate
    private BigInteger y; //y coordinate

    // n:=4r where r = 2^{446} -3818066809895115352007386748515426880336692474882178609894547503885.
    public static BigInteger r = BigInteger.TWO.pow(446).subtract(new BigInteger("13818066809895115352007386748515426880336692474882178609894547503885"));

    //Constructor for the neutral element curve point
    public ED448(){
        this.y = BigInteger.ONE;
        this.x = BigInteger.ZERO;
    }

    //Constructor for a curve point given x and y
    public ED448(BigInteger x, BigInteger y){
        this.x = x;
        this.y = y;
    }

    //Constructor for a curve point given y and the least significant bit of x(as a boolean here)
    public ED448(BigInteger y, boolean lsbx){
        this.y  = y ;


        BigInteger y2 = y.multiply(y);
        BigInteger radNum = BigInteger.ONE.subtract(y2);
        radNum = radNum.mod(p);

        BigInteger radDenom = BigInteger.ONE.add(BigInteger.valueOf(39081).multiply(y2));
        radDenom = radDenom.mod(p);
        radDenom = radDenom.modInverse(p);

        //BigInteger radicand = radNum.multiply(radDenom.modInverse(p)).mod(p);
        BigInteger radicand = radNum.multiply(radDenom);
        radicand = radicand.mod(p);
        this.x = sqrt(radicand, p, lsbx);
    }

    /**
     * public generator point for the eliptical curve with 𝑦0 = −3 (mod 𝑝) and 𝑥0 a certain unique even number
     * @param lsbx least significant bit for x
     * @return
     */
    public static ED448 ed448gen(boolean lsbx){
        BigInteger y0 = BigInteger.valueOf(3).negate().mod(p);
        return new ED448(y0, lsbx);
    }

    /**
     * checks to see if a given point is equal
      * @param point the eliptical point to compare to
     * @return true or false
     */
    public  boolean equals(ED448 point){
        return this.x.equals(point.getX()) && this.y.equals(point.getY());
    }

    /**
     * Method to obtain the opposite of a given point
     * @return the inverse of the point
     */
    public ED448 inverse(){
        return new ED448(p.subtract(this.x), this.y) ;
    }

    /**
     * uses edwards points addition formula to calulate the addition of two points
     * Reference: From assignment description
      * @param point the point to be added
     * @return the resulting point after addition
     */
    public ED448 add(ED448 point){

        BigInteger x2 = point.getX();
        BigInteger y2 = point.getY();
        BigInteger resx;
        BigInteger resy;

        //calculate x
        BigInteger xNum = this.x.multiply(y2).add(this.y.multiply(x2));
        xNum = xNum.mod(p);

        BigInteger xDenom = BigInteger.ONE.add(d.multiply(this.x).multiply(x2).multiply(this.y).multiply(y2));
        xDenom = xDenom.mod(p);
        xDenom = xDenom.modInverse(p);

        resx = xNum.multiply(xDenom);
        resx = resx.mod(p);

        //calulate y
        BigInteger yNum = this.y.multiply(y2).subtract(this.x.multiply(x2));
        yNum = yNum.mod(p);

        BigInteger yDenom = BigInteger.ONE.subtract(d.multiply(this.x).multiply(x2).multiply(this.y).multiply(y2));
        yDenom = yDenom.mod(p);
        yDenom = yDenom.modInverse(p);

        resy =  yNum.multiply(yDenom);
        resy = resy.mod(p);

        return new ED448(resx, resy);
    }


    /**
     * Method to compute the scalar multiple of a point
     * reference: Algorithim from Professor course slides
     * @param s scalar to multiply by
     * @return s*P
     */
    public ED448 scalMul(BigInteger s){
        if(s.equals(BigInteger.ZERO)){
            return new ED448();
        }
        // s = (sk sk-1 ... s1 s0)2, sk = 1
        ED448 P = new ED448(this.x, this.y);
        ED448 V = new ED448(this.x, this.y);// initialize with sk*P, which is simply P

        // Get the number of significant bits in the BigInteger
        int bitLength = s.bitLength();

        for (int i = bitLength - 2; i >= 0; i--) {// scan over the k bits of s
            boolean bitSet = s.testBit(i);
            V = V.add(V); // invoke the Edwards point addition formula
            if(bitSet){
                V = V.add(P);
            }
        }
        return V; // now finally V = s*P
    }


    /**
     * Compute a square root of v mod p with a specified least-significant bit
     * if such a root exists.
     *Reference: provided by Professor
     * @param v the radicand.
     * @param p the modulus (must satisfy p mod 4 = 3).
     * @param lsb desired least significant bit (true: 1, false: 0).
     * @return a square root r of v mod p with r mod 2 = 1 iff lsb = true
     * if such a root exists, otherwise null.
     */
    public static BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
        assert (p.testBit(0) && p.testBit(1)); // p = 3 (mod 4)
        if (v.signum() == 0) {
            return BigInteger.ZERO;
        }
        BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);
        if (r.testBit(0) != lsb) {
            r = p.subtract(r); // correct the lsb
        }
        return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
    }



    /**
     * getter method
     * @return x value for point
     */
    public BigInteger getX() {return x; }

    /**
     * getter method
     * @return y value for point
     */
    public BigInteger getY() {return y;}
}
