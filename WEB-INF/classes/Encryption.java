import java.math.BigInteger;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class Encryption {

    /*
    Alice:
    - two random primes p1,p2
    - multiply them together to get p
    - compute phi(p) which is (p1-1)*(p2-1)
    - small public exponent e, odd number and doesn't share a common factor with p
    - compute d = (k*phi(p)+1)/e, where k is anynumber
    - p and e make up public lock.
    - bob encryps his secret message number m as : m^(e) mod 3127 = c
    - alice decrypts the message by c^d mod n = m
     */
  
    /*
    Example:
    p1 = 4000631
    p2 = 3989641
    p = 4000631*3989641 =  15,961,081,463,471 = 15961081463471
    phi(p) = (4000631-1)*(3989641-1) = 15961073473200
    e = 3, k = 6
    d = (6*15961073473200+1)/3
    d =
     */
    private final static int[] PRIMES = {2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97};

    /**
     * Generate two keys; a public key and a private key.
     * The first is the private key and the second is the public key.
     * The public key has the exponent concatenated to the end with the last digit how long the exponent is.
     */
    public static String[] generateKeys(){
        String[] randomPrimes = getRandomPrimes();
        BigInteger p1BigInt = new BigInteger(randomPrimes[0]);
        BigInteger p2BigInt = new BigInteger(randomPrimes[1]);
        String publicKeyPre  = p1BigInt.multiply(p2BigInt).toString();
        String[] pke = computePrivateKeyAndE(p1BigInt,p2BigInt);
        String privateKey = pke[0];
        String publicKey = publicKeyPre + pke[1] + pke[1].length();
        return new String[]{privateKey,publicKey};
    }


    /**
     * Compute the secret code for encryption and compute e and k in the process.
     */
    private static String[] computePrivateKeyAndE(BigInteger p1BigInt, BigInteger p2BigInt) {
        BigInteger one = BigInteger.ONE;
        BigInteger p11 = p1BigInt.subtract(one);
        BigInteger p22 = p2BigInt.subtract(one);
        BigInteger phi = p11.multiply(p22);
        String e = Integer.toString(findE(phi));
        int k = findK(phi, Integer.parseInt(e));
        String privateKey = phi.multiply(BigInteger.valueOf(k)).add(one).divide(new BigInteger(e)).toString();
        return new String[]{privateKey,e};
    }


    /**
     * Get randomly selected primes numbers that are the same amoun of digits. Do this by using a database full of primes.
     * @return Two Strings as prime numbers.
     */
    public static String[] getRandomPrimes() {
        Random rand = new Random();
        String prime1String = "";
        String prime2String = "";
        int difference = 1;
        while (difference != 0) {
            int id1 = rand.nextInt(999000);
            int id2 = rand.nextInt(1000);
            prime1String = getPrimeFromDataBase("primes50Million",id1);
            prime2String = getPrimeFromDataBase("primes50Million",id1 + id2);
           difference = prime2String.length() - prime1String.length();
       }
        return new String[]{prime1String, prime2String};

    }


    /**
     * From the database retrieve a prime from a database of primes
     * @param id The number o the prime. must be positive and less than 1000,000
     * @return The String of the prime with id id.
     */
    private static String getPrimeFromDataBase(String table, int id){
            Connection conn = null;
            Statement stmt = null;
            try {
                // Step 1: Allocate a database Connection object
                Class.forName("com.mysql.jdbc.Driver");  // Needed for JDK9/Tomcat9
                conn = DriverManager.getConnection(
                        "jdbc:mysql://aaw2169yb11sbw.cx9sy8pgmasz.us-east-2.rds.amazonaws.com:3306/Primes?user=brysonmarazzi&password=bryson02"); // <== Check!
                // Step 2: Allocate a Statement object within the Connection
                stmt = conn.createStatement();
                // Step 3: Execute a SQL SELECT query
                String sqlStr = "select prime from " + table + "  where id = "+ id + ";";

                ResultSet result = stmt.executeQuery(sqlStr);  // Send the query to the server
                result.next();
                return result.getString("prime");

            }catch(Exception e) {
                System.out.println("Error Connecting To DB: " + e.getMessage());
            }
            return "Not Found";
    }


    /**
     * Encrypt a message from Plain text to cipher text using RSA encryption techniques. 
     * @param message The message to encrypt. 
     * @param publicKey The public Key used to encrypt given by user. Must contain only digits. 
     * @param e The exponent used in the formula to encrypt. Must contain only digits. 
     * @return The encrypted cipher string. 
     */
    public static String encrypt(String message, String e, String publicKey) {
        BigInteger N = new BigInteger(publicKey);
        BigInteger E = new BigInteger(e);
        String encrypted = convertToSmallerMessages(message, 3)  //break up the message into strings of length 3 with the last string an even length 3 with padding ofa a special character on the end
                .stream().map(s -> convertToDigits(s)) //convert each string to a 6 digit long number based on the ascii code
                .map(d -> new BigInteger(d)) //convert each number to a BigInteger
                .map(i -> computeC(i, E, N)) //compute c, each length will be 2*size of the primes
                .reduce("", (s1, s2) -> s1 + s2); //put them together
        return encrypted;
    }

    /**
     * Decrypt a message from cipher text to plain text. 
     * @param message The message (cipher text) to decrypt
     * @param secretCode The private key given by user. Must contain only digits. 
     * @param publicKey The public key given by user. Must contain only digits. 
     * @return
     */
    public static String decrypt(String message, String secretCode, String publicKey) {
        int size = (int) Math.ceil(publicKey.length() / 2.0);
        List<String> messages = convertToSmallerMessages(message, size * 2);
        String decryption = messages.stream()
                .map(s -> new BigInteger(s))
                .map(bigInt -> bigInt.modPow(new BigInteger(secretCode), new BigInteger(publicKey)).toString())
                .map(nums -> convertToWords(nums))
                .reduce("", (s1, s2) -> s1 + s2);
        return decryption;
    }
//INFORMATION TO ENCODE IN THE STRING ITSELF:
// - root to undo padding,
// - where the extra bits start, and end

    /**
     * Compute the variable c for the formula to encrypt/decrypt 
     * @param i The variable i. 
     * @param E The exponent. 
     * @param N The product of the two primes 
     * @return The variable C. 
     */
    private static String computeC(BigInteger i, BigInteger E, BigInteger N) {
        BigInteger c = i.modPow(E, N);
        String cString = c.toString();
        int size = (int) Math.ceil(N.toString().length() / 2.0);
        if (cString.length() < size * 2) {
            StringBuilder sb = new StringBuilder();
            for (int j = 0; j < size * 2 - cString.length(); j++) {
                sb.append("0");
            }
            sb.append(cString);
            assert (sb.toString().length() == size * 2);
            return sb.toString();
        }
        assert (cString.length() == size * 2);
        return cString;
    }


    /**
     * Convert a message of any type of character to two digit digits based on ascii code - 32. (Since space is 32 and the lowest number.
     * ***Does not support the following: {}| ~ - those result in a digit less than 10.
     *
     * @param message The string to convert.
     * @return int that represents the word.
     */
    private static String convertToDigits(String message) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < message.length(); i++) {
            int ascii = (int) message.charAt(i);
            if (ascii - 31 < 10) sb.append("0");
            sb.append(ascii - 31);
        }
        return sb.toString();
    }


    /**
     * Convert integers to words using ascii codes.
     *
     * @param nums The nums to convert. String must contain alphanumeric characters.
     *             nums must have an even length. the ascii codes of nums are expected to have been subtracted by 32.
     * @return The word converted.
     */
    private static String convertToWords(String nums) {
        //every other number should be converted to a string
        StringBuilder sbCorrect = new StringBuilder();
        if (nums.length() < 6) {
            sbCorrect.append("0");
        }
        sbCorrect.append(nums);

        String numsCorrected = sbCorrect.toString();
        int prevIndex = 0;
        StringBuilder sb = new StringBuilder();
        for (int i = 2; i <= numsCorrected.length(); i += 2) {
            int ascii = Integer.parseInt(numsCorrected.substring(prevIndex, i)) + 31;
            if (ascii != 128) sb.append(((char) ascii));
            prevIndex = i;
        }
        return sb.toString();
    }

    /**
     * Split up the message into a list of strings of a given length.
     * The rest of the message is appended to the end if the length is not divisible by the given number and special characters are added to make it full.
     *
     * @param message     The message to split up.
     * @param splitLength The length of all the split words
     * @return The list.
     */
    private static List<String> convertToSmallerMessages(String message, int splitLength) {
        List<String> messages = new ArrayList<>();
        int stop = message.length() / splitLength;
        int index = 0;
        for (int i = 0; i < stop; i++) {
            StringBuilder sb = new StringBuilder();
            for (int j = 0; j < splitLength; j++) {
                sb.append(message.charAt(index));
                index++;
            }
            messages.add(sb.toString());
        }

        int remainingPart = message.length() % splitLength;
        if (remainingPart > 0) {
            StringBuilder sb = new StringBuilder();
            for (int k = 0; k < remainingPart; k++) {
                sb.append(message.charAt(index));
                index++;
            }
            int remainingMinusSplitLength = sb.toString().length();
            for (int l = 0; l < splitLength - remainingMinusSplitLength; l++) {
                sb.append((char) 128);        //pad the ends with an unprintable character to distinguish it.
            }
            messages.add(sb.toString());
        }

        return messages;
    }


    /**
     * Find the value of k such that (k*phi(p)+1)/e is a whole number,
     *
     * @param phi A variable in the equation
     * @param e   the value of e
     * @return k
     */
    private static int findK(BigInteger phi, int e) {
        int k = 0;
        BigInteger mod = BigInteger.ONE;
        while (mod.compareTo(BigInteger.ZERO) != 0) {
            k++;
            mod = phi.multiply(BigInteger.valueOf(k)).add(BigInteger.ONE).mod(BigInteger.valueOf(e));
        }
        return k;
    }

    /**
     * Find the smallest number that doesn't share any common factors with a given number.
     *
     * @param p The given number
     * @return The lowest number.
     */
    private static int findE(BigInteger p) {
        BigInteger mod = BigInteger.ZERO;
        int prime=1;
        int count = 0;
        while (mod.compareTo(BigInteger.ZERO) == 0 && count < PRIMES.length) {
            prime = PRIMES[count];
            mod = p.mod(BigInteger.valueOf(prime));
            count++;
        }
        return prime;
    }



}