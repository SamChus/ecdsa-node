import React from "react";
import { generateMnemonic } from "bip39";

const BackupWallet = ({ onBackupMnemonic, onBackupKeystore }) => {
  const handleBackup = async () => {
    const mnemonic = generateMnemonic();
    const password = prompt(
      "Enter a password to encrypt your seed phrase backup:"
    );
    if (password) {
      onBackupMnemonic(mnemonic, password);
      alert("Seed phrase backup created. Please store it securely!");
    } else {
      alert("Password cannot be empty. Seed phrase backup not created.");
    }
  };

  const downloadKeystore = (keystore) => {
    const filename = "keystore.json";
    const json = JSON.stringify(keystore, null, 2);
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    alert("Keystore file downloaded. Please store it securely!");
  };

  return (
    <div>
      <h2>Backup Wallet</h2>
      <button onClick={handleBackup}>Backup Seed Phrase</button>
      <button onClick={() => onBackupKeystore(downloadKeystore)}>
        Download Keystore
      </button>
    </div>
  );
};

export default BackupWallet;
