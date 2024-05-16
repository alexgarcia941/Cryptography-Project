import java.math.BigInteger;

/**
 *ED448 Ed448-Goldilocks curve (an Edwards Curve)
 * defined by prime number p and a curve equation
 * p:=2^{448}-2^{224}-1, a prime number defining finite field F_p
 * Curve Equation: (x^2 + y^2) = 1 + dx^{2}y^{2} with d = -39081
 * @author Alex Garcia
 */
public class ED448 {
    private BigInteger p;
    private BigInteger d;
    private BigInteger x;
    private BigInteger y;
}
