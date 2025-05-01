import { useState } from "react";
import server from "./server";
import { keccak256 } from "ethereum-cryptography/keccak";
import { secp256k1 } from "ethereum-cryptography/secp256k1";
import { utf8ToBytes, toHex } from "ethereum-cryptography/utils";

function Transfer({ address, setBalance }) {
  const [sendAmount, setSendAmount] = useState("");
  const [recipient, setRecipient] = useState("");

  const setValue = (setter) => (evt) => setter(evt.target.value);

  async function transfer(evt) {
    evt.preventDefault();

    const password = window.prompt("Please enter your password to confirm the transaction:");
    if (!password) {
      alert("Transaction cancelled");
      return;
    }

    const prompt = window.confirm(
      `Are you sure you want to send ${sendAmount} to ${recipient}?`
    );


    const transactionHash = keccak256(
      utf8ToBytes(
        JSON.stringify({
          sender: address,
          recipient,
          amount: parseInt(sendAmount),
        })
      )
    );

    const privateKeyHex = localStorage.getItem("privateKey");
    const publicKeyHex = localStorage.getItem("publicKey");

    if (!privateKeyHex || !publicKeyHex) {
      console.error("Missing private or public key");
      return;
    }

    // Convert hex keys to Uint8Array
    const privateKeyBytes = Uint8Array.from(Buffer.from(privateKeyHex, "hex"));
    const publicKeyBytes = Uint8Array.from(Buffer.from(publicKeyHex, "hex"));

    const signature = await secp256k1.sign(transactionHash, privateKeyBytes);
    const signatureBytes = signature.toCompactRawBytes();

    try {
      console.log("calling server");
      const { data } = await server.post(`send`, {
        sender: address,
        recipient,
        amount: parseInt(sendAmount),
        signature: toHex(signatureBytes),
        transactionHash: toHex(transactionHash),
        publicKey: toHex(publicKeyBytes),
      });
      console.log("response", data);
      setBalance(data.balance);
    } catch (ex) {
      console.error(ex);
    }
  }

  return (
    <form className="container transfer" onSubmit={transfer}>
      <h1>Send Transaction</h1>

      <label>
        Send Amount
        <input
          placeholder="1, 2, 3..."
          value={sendAmount}
          onChange={setValue(setSendAmount)}
        />
      </label>

      <label>
        Recipient
        <input
          placeholder="Type an address, for example: 0x2"
          value={recipient}
          onChange={setValue(setRecipient)}
        />
      </label>

      <input type="submit" className="button" value="Transfer" />
    </form>
  );
}

export default Transfer;
