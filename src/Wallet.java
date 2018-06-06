import java.security.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.security.spec.ECGenParameterSpec;
import java.util.Map;

public class Wallet {
    public PrivateKey privateKey;
    public PublicKey publicKey;
    public HashMap<String,TransactionOutput> TOs = new HashMap<String,TransactionOutput>();

    public Wallet() {
        generateKeyPair();
    }

    public void generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA","BC");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec("prime192v1");
            keyGen.initialize(ecSpec, random);
            KeyPair keyPair = keyGen.generateKeyPair();
            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();
        }
        catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public float getBalance() {
        float total = 0;
        for (Map.Entry<String, TransactionOutput> item: Blockchain.TOs.entrySet()) {
            TransactionOutput TO = item.getValue();
            if(TO.isMine(publicKey)) { //if output belongs to me ( if coins belong to me )
                TOs.put(TO.id,TO); //add it to our list of unspent transactions.
                total += TO.value ;
            }
        }
        return total;
    }

    public Transaction sendFunds(PublicKey receiver, float value) {
        if (getBalance() < value) {
            System.out.println("Not enough funds");
            return null;
        }
        ArrayList<TransactionInput> inputs = new ArrayList<TransactionInput>();
        float total = 0;

        for (Map.Entry<String, TransactionOutput> item: TOs.entrySet()) {
            TransactionOutput TO = item.getValue();
            total += TO.value;
            inputs.add(new TransactionInput(TO.id));
            if(total > value) break;
        }

        Transaction newTransaction = new Transaction(publicKey, receiver , value, inputs);
        newTransaction.generateSignature(privateKey);

        for(TransactionInput input: inputs) {
            TOs.remove(input.transactionOutputId);
        }
        return newTransaction;
    }
}
