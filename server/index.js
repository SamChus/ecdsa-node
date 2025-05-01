const express = require("express");
const app = express();
const cors = require("cors");
const port = 3042;

const { sha256 } = require("ethereum-cryptography/sha256");
const { toHex, utf8ToBytes } = require("ethereum-cryptography/utils");
const { secp256k1 } = require("ethereum-cryptography/secp256k1");
const { keccak256 } = require("ethereum-cryptography/keccak");

app.use(cors());
app.use(express.json());



const balances = {
  "0x3E32251BA5E9E2ADBFBB1184790BDBF546A563CB": 100,
  "03749e05dd4aea6fce25f6cfa99be85ecb0495c95fa2ed7fbd59c6d511c2629540": 50,
  "029406d33180a7a4134c3c5970ebdd74f70f5d66c1bd283be71e9cf82d585dd701": 75,
};




app.get("/balance/:address", (req, res) => {
  const { address } = req.params;
  const balance = balances[address] || 0;
  res.send({ balance });
});

app.post("/send", (req, res) => {
  const { sender, recipient, amount, signature, transactionHash, publicKey } = req.body;

  console.log("Received request:", req.body);

  if (!transactionHash) {
    return res.status(400).send({ message: "Transaction hash is missing!" });
  }

  const isSignatureValid = secp256k1.verify(
    signature,
    Uint8Array.from(Buffer.from(transactionHash, "hex")),
    publicKey
  );

  if (isSignatureValid) {
    setInitialBalance(sender);
    setInitialBalance(recipient);
  
    if (balances[sender] < amount) {
      res.status(400).send({ message: "Not enough funds!" });
    } else {
      balances[sender] -= amount;
      balances[recipient] += amount;
      res.send({ balance: balances[sender] });
    }
    
  }

  else {
    res.status(400).send({ message: "Invalid signature!" });
  }
  console.log("Balances after transaction:", balances);
  console.log("Signature valid:", isSignatureValid);
  console.log("Sender balance:", balances[sender]);

});

app.listen(port, () => {
  console.log(`Listening on port ${port}!`);
});

function setInitialBalance(address) {
  if (!balances[address]) {
    balances[address] = 0;
  }
}
