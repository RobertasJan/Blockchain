import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;

public class Transaction {
    public String transactionId;
    public PublicKey sender;
    public PublicKey receiver;
    public float value;
    public byte[] signature;

    public ArrayList<TransactionInput> inputs = new ArrayList<TransactionInput>();
    public ArrayList<TransactionOutput> outputs = new ArrayList<TransactionOutput>();

    private static int sequance = 0;

    public Transaction(PublicKey from, PublicKey to, float value,  ArrayList<TransactionInput> inputs) {
        this.sender = from;
        this.receiver = to;
        this.value = value;
        this.inputs = inputs;
    }

    public void generateSignature(PrivateKey privateKey) {
        String data = StringHelper.getStringFromKey(sender) + StringHelper.getStringFromKey(receiver) + Float.toString(value);
        signature = StringHelper.applyECDSASig(privateKey, data);
    }

    public boolean verifySignature() {
        String data = StringHelper.getStringFromKey(sender) + StringHelper.getStringFromKey(receiver) + Float.toString(value);
        return StringHelper.verifyECDSASig(sender, data, signature);
    }

    private String calculateHash() {
        sequance++;
        return StringHelper.encryption(StringHelper.getStringFromKey(sender) + StringHelper.getStringFromKey(receiver) + Float.toString(value) + sequance);
    }

    public boolean proccessTransaction() {
        if (!verifySignature()) {
            System.out.println("#Transaction Signuture failed to verify");
            return false;
        }

        for (TransactionInput i : inputs) {
            i.TO = Blockchain.TOs.get(i.transactionOutputId);
        }

        if (getInputsValue() < Blockchain.minimumTransaction) {
            System.out.println("#Transaction Inputs to small: " + getInputsValue());
            return false;
        }

        float leftOver = getInputsValue() - value;
        transactionId = calculateHash();
        outputs.add(new TransactionOutput(this.receiver, value, transactionId));
        outputs.add(new TransactionOutput(this.sender, leftOver, transactionId));

        for (TransactionOutput o : outputs) {
            Blockchain.TOs.put(o.id, o);
        }

        for (TransactionInput i : inputs) {
            if (i.TO == null)
                continue;
            Blockchain.TOs.remove(i.TO.id);
        }

        return true;
    }

    public float getInputsValue() {
        float total = 0;
        for (TransactionInput i : inputs) {
            if (i.TO == null)
                continue;
            total+=i.TO.value;
        }
        return total;
    }

    public float getOutputsValue() {
        float total = 0;
        for(TransactionOutput o : outputs) {
            total += o.value;
        }
        return total;
    }
}
