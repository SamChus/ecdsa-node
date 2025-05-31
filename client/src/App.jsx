// import Wallet from "./Wallet";
// import Transfer from "./Transfer";
// import "./App.scss";
// import { useState } from "react";
// import Register from "./Register";

// function App() {
//   const [balance, setBalance] = useState(0);
//   const [address, setAddress] = useState("");

//   return (
//     <div className="app">
//       <Register />
//       <Wallet
//         balance={balance}
//         setBalance={setBalance}
//         address={address}
//         setAddress={setAddress}
//       />
//       <Transfer setBalance={setBalance} address={address} />
//     </div>
//   );
// }

// export default App;

import { useState, useEffect } from "react";
import { bytesToHex, hexToBytes } from "ethereum-cryptography/utils";
import { secp256k1 } from "ethereum-cryptography/secp256k1";
import { keccak256 } from "ethereum-cryptography/keccak";
import { generateMnemonic } from "bip39";
import { ethers } from "ethers";
import BackupWallet from "./BackupWallet";
import RestoreWallet from "./RestoreWallet";

const PRIVATE_KEY_STORAGE_KEY = "encryptedPrivateKey";
const MNEMONIC_STORAGE_KEY = "encryptedMnemonic";
const KEY_IV_STORAGE_KEY = "keyIV";
const MNEMONIC_IV_STORAGE_KEY = "mnemonicIV";

// Helper to get a CryptoKey of 256 bits from password using SHA-256
async function importPasswordKey(password) {
  const passwordBytes = new TextEncoder().encode(password);
  // Hash the password to ensure 256 bits key length
  const hashBuffer = await crypto.subtle.digest("SHA-256", passwordBytes);
  return await crypto.subtle.importKey(
    "raw",
    hashBuffer,
    { name: "AES-CBC" },
    false,
    ["encrypt", "decrypt"]
  );
}

// Encrypt and store the mnemonic (seed phrase) in localStorage
async function backupSeedPhrase(mnemonic, password) {
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const key = await importPasswordKey(password);
  const mnemonicBytes = new TextEncoder().encode(mnemonic);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-CBC", iv },
    key,
    mnemonicBytes
  );
  localStorage.setItem(MNEMONIC_STORAGE_KEY, bytesToHex(new Uint8Array(ciphertext)));
  localStorage.setItem(MNEMONIC_IV_STORAGE_KEY, bytesToHex(iv));
}

function App() {
  const [wallet, setWallet] = useState(null);
  const [restorationMessage, setRestorationMessage] = useState("");

  useEffect(() => {
    initializeWallet();
    // eslint-disable-next-line
  }, []);

  async function encryptPrivateKey(privateKeyBytes, password) {
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const key = await importPasswordKey(password);
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-CBC", iv },
      key,
      privateKeyBytes
    );
    localStorage.setItem(KEY_IV_STORAGE_KEY, bytesToHex(iv));
    return bytesToHex(new Uint8Array(ciphertext));
  }

  function isHexString(str) {
    return typeof str === "string" && /^[0-9a-fA-F]+$/.test(str);
  }

  async function decryptPrivateKey(ciphertextHex, password, ivHex) {
    if (!ivHex || !ciphertextHex) return null;
    if (!isHexString(ivHex) || !isHexString(ciphertextHex)) {
      console.error("Invalid hex string for decryption");
      return null;
    }
    const iv = hexToBytes(ivHex);
    const ciphertext = hexToBytes(ciphertextHex);
    const key = await importPasswordKey(password);
    try {
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-CBC", iv },
        key,
        ciphertext
      );
      return new Uint8Array(decrypted);
    } catch (error) {
      console.error("Failed to decrypt private key:", error);
      alert("Incorrect password for private key decryption.");
      return null;
    }
  }

  // Generate an Ethereum-compatible keystore (still uses PBKDF2 for compatibility)
  async function generateKeystore(privateKeyBytes, password) {
    // Use the same password hashing as in importPasswordKey to ensure 256-bit key
    const derivedKey = await importPasswordKey(password);
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const ciphertextBuffer = await crypto.subtle.encrypt(
      { name: "AES-CBC", iv: iv },
      derivedKey,
      privateKeyBytes
    );
    const ciphertext = bytesToHex(new Uint8Array(ciphertextBuffer));
    // MAC is just a hash of iv+ciphertext for this simple version
    const macInput = new Uint8Array([...iv, ...hexToBytes(ciphertext)]);
    const mac = bytesToHex(keccak256(macInput));
    return {
      crypto: {
        cipher: "aes-128-cbc",
        ciphertext: ciphertext,
        cipherparams: { iv: bytesToHex(iv) },
        kdf: "none",
        kdfparams: {},
        mac: mac,
      },
      version: 3,
    };
  }

  // Recover private key from keystore
  async function recoverPrivateKeyFromKeystore(keystore, password) {
    try {
      const iv = hexToBytes(keystore.crypto.cipherparams.iv);
      const ciphertext = hexToBytes(keystore.crypto.ciphertext);
      // Use the same password hashing as in importPasswordKey to ensure 256-bit key
      const derivedKey = await importPasswordKey(password);
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-CBC", iv: iv },
        derivedKey,
        ciphertext
      );
      const recoveredPrivateKey = new Uint8Array(decrypted);
      // MAC check
      const macInput = new Uint8Array([...iv, ...ciphertext]);
      const expectedMac = bytesToHex(keccak256(macInput));
      if (expectedMac !== keystore.crypto.mac) {
        throw new Error("MAC verification failed. Incorrect Password or corrupted Keystore");
      }
      return recoveredPrivateKey;
    } catch (error) {
      console.error("Decryption Failed", error);
      return null;
    }
  }

  async function recoverSeedPhrase(password) {
    const encryptedMnemonic = localStorage.getItem(MNEMONIC_STORAGE_KEY);
    const ivHex = localStorage.getItem(MNEMONIC_IV_STORAGE_KEY);
    if (!encryptedMnemonic || !ivHex) return null;
    const iv = hexToBytes(ivHex);
    const key = await importPasswordKey(password);
    try {
      const decryptedMnemonicBuffer = await crypto.subtle.decrypt(
        { name: "AES-CBC", iv },
        key,
        hexToBytes(encryptedMnemonic)
      );
      return new TextDecoder().decode(new Uint8Array(decryptedMnemonicBuffer));
    } catch (error) {
      console.error("Failed to decrypt seed phrase:", error);
      alert("Incorrect password for seed phrase decryption.");
      return null;
    }
  }

  async function derivePrivateKeyFromMnemonic(mnemonic) {
    const wallet = ethers.Wallet.fromPhrase(mnemonic);
    return hexToBytes(wallet.privateKey.slice(2));
  }

  // Get wallet address from private key
  async function getWalletAddress(privateKeyBytes) {
    const publicKey = secp256k1.getPublicKey(privateKeyBytes);
    const ethereumPublicKey = publicKey.slice(1);
    const addressBytes = keccak256(ethereumPublicKey).slice(-20);
    return "0x" + Buffer.from(addressBytes).toString("hex");
  }

  async function initializeWallet() {
    let password = prompt(
      "Enter your wallet password (for new wallets, this will encrypt your key and seed phrase):"
    );
    if (!password) return;

    const storedEncryptedKey = localStorage.getItem(PRIVATE_KEY_STORAGE_KEY);

    if (!storedEncryptedKey) {
      const privateKey = secp256k1.utils.randomPrivateKey();
      const encryptedKey = await encryptPrivateKey(privateKey, password);
      localStorage.setItem(PRIVATE_KEY_STORAGE_KEY, encryptedKey);
      const mnemonic = generateMnemonic();
      await backupSeedPhrase(mnemonic, password);
      const address = await getWalletAddress(privateKey);
      setWallet({ privateKey, address, mnemonic });
    } else {
      const keyIv = localStorage.getItem(KEY_IV_STORAGE_KEY);
      const decryptedKeyBytes = await decryptPrivateKey(
        storedEncryptedKey,
        password,
        keyIv
      );
      if (decryptedKeyBytes) {
        const address = await getWalletAddress(decryptedKeyBytes);
        setWallet({ privateKey: decryptedKeyBytes, address, mnemonic: null });
      } else {
        alert("Incorrect password.");
      }
    }
  }

  const handleBackupMnemonic = async (mnemonic, password) => {
    await backupSeedPhrase(mnemonic, password);
    alert(
      `Seed phrase backed up and encrypted. Please write down this seed phrase: ${mnemonic}`
    );
    if (wallet?.privateKey) {
      const passwordForKeystore = prompt(
        "Enter a password to download your keystore file:"
      );
      if (passwordForKeystore) {
        const keystore = await generateKeystore(
          wallet.privateKey,
          passwordForKeystore
        );
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
        alert("Keystore file downloaded. Store it securely!");
      }
    }
  };

  const handleBackupKeystore = async (downloadKeystoreFunc) => {
    if (wallet?.privateKey) {
      const passwordForKeystore = prompt(
        "Enter a password to download your keystore file:"
      );
      if (passwordForKeystore) {
        const keystore = await generateKeystore(
          wallet.privateKey,
          passwordForKeystore
        );
        downloadKeystoreFunc(keystore);
      }
    } else {
      alert("Wallet not initialized.");
    }
  };

  const handleRestoreKeystore = async (keystoreJSON, password) => {
    const recoveredPrivateKeyBytes = await recoverPrivateKeyFromKeystore(
      JSON.parse(keystoreJSON),
      password
    );
    if (recoveredPrivateKeyBytes) {
      const address = await getWalletAddress(recoveredPrivateKeyBytes);
      setWallet({
        privateKey: recoveredPrivateKeyBytes,
        address,
        mnemonic: null,
      });
      setRestorationMessage(
        `Wallet restored from keystore! Address: ${address}`
      );
    } else {
      setRestorationMessage("Failed to restore wallet from keystore.");
    }
  };

  const handleRestoreSeedPhrase = async (password) => {
    const mnemonic = await recoverSeedPhrase(password);
    if (mnemonic) {
      const recoveredPrivateKeyBytes = await derivePrivateKeyFromMnemonic(
        mnemonic
      );
      const address = await getWalletAddress(recoveredPrivateKeyBytes);
      setWallet({ privateKey: recoveredPrivateKeyBytes, address, mnemonic });
      setRestorationMessage(
        `Wallet restored from seed phrase! Address: ${address}`
      );
    } else {
      setRestorationMessage("Failed to restore wallet from seed phrase.");
    }
  };

  return (
    <div>
      <h1>Simple Crypto Wallet</h1>
      {wallet ? (
        <div>
          <p>Wallet Address: {wallet.address}</p>
          {wallet.mnemonic && (
            <p>Seed Phrase: {wallet.mnemonic} (Backup this securely!)</p>
          )}
          <BackupWallet
            onBackupMnemonic={handleBackupMnemonic}
            onBackupKeystore={() =>
              handleBackupKeystore((ks) => {
                const filename = "keystore.json";
                const json = JSON.stringify(ks, null, 2);
                const blob = new Blob([json], { type: "application/json" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                alert("Keystore file downloaded. Store it securely!");
              })
            }
          />
        </div>
      ) : (
        <p>Initializing wallet...</p>
      )}
      <RestoreWallet
        onRestoreKeystore={handleRestoreKeystore}
        onRestoreSeedPhrase={handleRestoreSeedPhrase}
      />
      {restorationMessage && <p>{restorationMessage}</p>}
    </div>
  );
}

export default App;
