import React, { useState } from "react";

const RestoreWallet = ({ onRestoreKeystore, onRestoreSeedPhrase }) => {
  const [keystoreFile, setKeystoreFile] = useState(null);
  const [seedPhrasePassword, setSeedPhrasePassword] = useState("");

  const handleKeystoreFileChange = (event) => {
    setKeystoreFile(event.target.files[0]);
  };

  const handleRestoreKeystore = async () => {
    if (keystoreFile) {
      const reader = new FileReader();
      reader.onload = async (event) => {
        const keystoreJSON = event.target.result;
        const password = prompt("Enter the password for your keystore file:");
        if (password) {
          onRestoreKeystore(keystoreJSON, password);
        }
      };
      reader.readAsText(keystoreFile);
    } else {
      alert("Please select a keystore file.");
    }
  };

  const handleRestoreSeedPhrase = async () => {
    const password = prompt(
      "Enter the password used to encrypt your seed phrase:"
    );
    if (password) {
      onRestoreSeedPhrase(password);
    }
  };

  return (
    <div>
      <h2>Restore Wallet</h2>
      <div>
        <input type="file" accept=".json" onChange={handleKeystoreFileChange} />
        <button onClick={handleRestoreKeystore}>Restore from Keystore</button>
      </div>
      <div style={{ marginTop: "10px" }}>
        <button onClick={handleRestoreSeedPhrase}>
          Restore from Seed Phrase
        </button>
      </div>
    </div>
  );
};

export default RestoreWallet;
