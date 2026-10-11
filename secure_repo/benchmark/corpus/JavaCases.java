import javax.crypto.Cipher;

class JavaCases {
    void run(String user) throws Exception {
        Runtime.getRuntime().exec("ping " + user); // expect: SR-JAVA-001
        Cipher weak = Cipher.getInstance("DES"); // expect: SR-JAVA-004
        // Runtime.getRuntime().exec(command) inside a comment must not match
        String doc = "Never call Runtime.getRuntime().exec(input)";
        /* Cipher.getInstance("DES") in a block comment must not match */
    }
}
