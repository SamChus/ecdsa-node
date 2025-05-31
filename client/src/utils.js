import { bytesToHex, hexToBytes } from 'ethereum-cryptography/utils';
import { secp256k1 } from 'ethereum-cryptography/secp256k1';
import { keccak256 } from 'ethereum-cryptography/keccak';
import { generateMnemonic, mnemonicToSeedSync } from 'bip39'; // For seed phrase
import { hdkey } from 'hdkey'; // For hierarchical deterministic keys

const PRIVATE_KEY_STORAGE_KEY = 'encryptedPrivateKey';
const MNEMONIC_STORAGE_KEY = 'encryptedMnemonic'; // Store encrypted mnemonic
const SALT_STORAGE_KEY = 'encryptionSalt';

// --- Keystore Functions (as before) ---
async function deriveKeyFromPassword(password, salt) {
    const passwordBytes = new TextEncoder().encode(password);
    const saltBytes = new TextEncoder().encode(salt);
    return await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: saltBytes,
            iterations: 100000,
            hash: 'SHA-256',
        },
        await crypto.subtle.importKey('raw', passwordBytes, { name: 'PBKDF2' }, false, ['deriveKey']),
        { name: 'AES-CBC', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

async function encryptPrivateKey(privateKeyBytes, password) {
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKeyFromPassword(password, bytesToHex(salt));
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-CBC', iv },
        key,
        privateKeyBytes
    );
    localStorage.setItem(SALT_STORAGE_KEY, bytesToHex(salt));
    return {
        ciphertext: bytesToHex(new Uint8Array(ciphertext)),
        iv: bytesToHex(iv),
    };
}

async function decryptPrivateKey(ciphertextHex, password, ivHex) {
    const saltHex = localStorage.getItem(SALT_STORAGE_KEY);
    if (!saltHex) {
        console.error("Salt not found.");
        return null;
    }
    const salt = hexToBytes(saltHex);
    const iv = hexToBytes(ivHex);
    const ciphertext = hexToBytes(ciphertextHex);
    const key = await deriveKeyFromPassword(password, saltHex);
    try {
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-CBC', iv },
            key,
            ciphertext
        );
        return new Uint8Array(decrypted);
    } catch (error) {
        console.error("Decryption error:", error);
        return null;
    }
}

async function generateKeystore(privateKeyBytes, password) {
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const derivedKey = await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256',
        },
        await crypto.subtle.importKey('raw', new TextEncoder().encode(password), { name: 'PBKDF2' }, false, ['deriveKey']),
        { name: 'AES-CBC', length: 128 },
        false,
        ['encrypt', 'decrypt']
    );

    const iv = crypto.getRandomValues(new Uint8Array(16));
    const ciphertextBuffer = await crypto.subtle.encrypt(
        { name: 'AES-CBC', iv: iv },
        derivedKey,
        privateKeyBytes
    );
    const ciphertext = bytesToHex(new Uint8Array(ciphertextBuffer));

      const macKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      await crypto.subtle.importKey("raw", new TextEncoder().encode(password), {name: 'PBKDF2'}, false, ['deriveKey']),
      {name: 'HMAC', hash: 'SHA-256'},
      false,
      ['sign']
    );
    const macInput = new Uint8Array([...iv, ...hexToBytes(ciphertext)]);
    const macBuffer = await crypto.subtle.sign('HMAC', macKey, macInput);
    const mac = bytesToHex(new Uint8Array(macBuffer));


    const keystore = {
        crypto: {
            cipher: 'aes-128-cbc',
            ciphertext: ciphertext,
            cipherparams: {
                iv: bytesToHex(iv),
            },
            kdf: 'pbkdf2',
            kdfparams: {
                salt: bytesToHex(salt),
                c: 100000,
                dklen: 16,
                prf: 'hmac-sha256'
            },
             mac: mac,
        },
        version: 3,
    };

    return keystore;
}

async function recoverPrivateKeyFromKeystore(keystore, password) {
     try{
    const salt = hexToBytes(keystore.crypto.kdfparams.salt);
    const iv = hexToBytes(keystore.crypto.cipherparams.iv);
    const ciphertext = hexToBytes(keystore.crypto.ciphertext);

    const derivedKey = await crypto.subtle.deriveKey(
      {
          name: 'PBKDF2',
          salt: salt,
          iterations: keystore.crypto.kdfparams.c,
          hash: 'SHA-256',
      },
      await crypto.subtle.importKey('raw', new TextEncoder().encode(password), { name: 'PBKDF2' }, false, ['deriveKey']),
      { name: 'AES-CBC', length: 128 },
      false,
      ['encrypt', 'decrypt']
    );

    const decrypted = await crypto.subtle.decrypt({name: 'AES-CBC', iv: iv}, derivedKey, ciphertext);
    const recoveredPrivateKey = new Uint8Array(decrypted);

      const macKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: keystore.crypto.kdfparams.c,
        hash: 'SHA-256'
      },
      await crypto.subtle.importKey("raw", new TextEncoder().encode(password), {name: 'PBKDF2'}, false, ['deriveKey']),
      {name: 'HMAC', hash: 'SHA-256'},
      false,
      ['sign']
    );
    const macInput = new Uint8Array([...iv, ...ciphertext]);
    const expectedMacBuffer = await crypto.subtle.sign('HMAC', macKey, macInput);
    const expectedMac = bytesToHex(new Uint8Array(expectedMacBuffer));

    if (expectedMac !== keystore.crypto.mac){
      throw new Error("MAC verification failed. Incorrect Password or corrupted Keystore")
    }
    return recoveredPrivateKey;

  } catch (error){
    console.error("Decryption Failed", error);
    return null;
  }
}

// --- Seed Phrase Functions ---
async function backupWithSeedPhrase() {
    const mnemonic = generateMnemonic(); // Generate the seed phrase
    const password = prompt('Enter a password to encrypt your seed phrase backup:');
    if (!password) {
        alert('Password cannot be empty. Seed phrase backup not created.');
        return null;
    }
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const derivedKey = await deriveKeyFromPassword(password, bytesToHex(salt));
    const mnemonicBytes = new TextEncoder().encode(mnemonic);
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const encryptedMnemonicBuffer = await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, derivedKey, mnemonicBytes);
    const encryptedMnemonic = bytesToHex(new Uint8Array(encryptedMnemonicBuffer));

    localStorage.setItem(MNEMONIC_STORAGE_KEY, encryptedMnemonic);
    localStorage.setItem(SALT_STORAGE_KEY, bytesToHex(salt)); //Use the same salt.
    localStorage.setItem('mnemonicIV', bytesToHex(iv));  // Store the IV for mnemonic

    alert(`Your seed phrase is: ${mnemonic}\nWrite this down and store it securely!\nYour seed phrase has also been encrypted and stored.`);
    return mnemonic; // Return the mnemonic for immediate use (optional)
}

async function recoverSeedPhrase(password) {
    const encryptedMnemonic = localStorage.getItem(MNEMONIC_STORAGE_KEY);
    const saltHex = localStorage.getItem(SALT_STORAGE_KEY);
      const ivHex = localStorage.getItem('mnemonicIV');
    if (!encryptedMnemonic || !saltHex || !ivHex) {
        alert('No encrypted seed phrase found.');
        return null;
    }
    const salt = hexToBytes(saltHex);
    const iv = hexToBytes(ivHex);
    const derivedKey = await deriveKeyFromPassword(password, saltHex);
    try {
        const decryptedMnemonicBuffer = await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, derivedKey, hexToBytes(encryptedMnemonic));
        const decryptedMnemonic = new TextDecoder().decode(new Uint8Array(decryptedMnemonicBuffer));
        return decryptedMnemonic;
    } catch (error) {
        console.error('Failed to decrypt seed phrase:', error);
        alert('Incorrect password for seed phrase decryption.');
        return null;
    }
}

// --- Wallet Functions ---
async function getWalletAddress(privateKeyBytes) {
    const publicKey = secp256k1.getPublicKey(privateKeyBytes);
    const ethereumPublicKey = publicKey.slice(1);
    const addressBytes = keccak256(ethereumPublicKey).slice(-20);
    return '0x' + Buffer.from(addressBytes).toString('hex');
}

// --- Initialization and Recovery ---
async function initializeWallet() {
    let password = prompt("Enter your wallet password (for new wallets, this will encrypt your key and seed phrase):");
    if (!password) {
        alert("Password cannot be empty.");
        return null;
    }

    const storedEncryptedKey = localStorage.getItem(PRIVATE_KEY_STORAGE_KEY);

    if (!storedEncryptedKey) {
        // New wallet: generate key, seed phrase, and encrypt
        const privateKey = secp256k1.generatePrivateKey();
        const { ciphertext, iv: keyIv } = await encryptPrivateKey(privateKey, password);
        localStorage.setItem(PRIVATE_KEY_STORAGE_KEY, ciphertext);
        localStorage.setItem('keyIV', keyIv);

        const mnemonic = await backupWithSeedPhrase(); // Generate and store seed phrase
        if (!mnemonic) {
          return null; //If mnemonic fails, stop.
        }
        const address = await getWalletAddress(privateKey);
        console.log('New wallet created. Address:', address);
        return { privateKey, address, mnemonic }; // Return mnemonic
    } else {
        // Returning user: decrypt and get address
        const keyIv = localStorage.getItem('keyIV');
        const decryptedKey = await decryptPrivateKey(storedEncryptedKey, password, keyIv);
        if (decryptedKey) {
            const address = await getWalletAddress(decryptedKey);
            console.log('Wallet loaded. Address:', address);
            return { privateKey: decryptedKey, address, mnemonic: null }; // mnemonic: null, we don't want to return it unless восстановление
        } else {
            alert("Incorrect password.");
            return null;
        }
    }
}

async function recoverWalletFromKeystoreFile(file) {
      const restorationMessageDiv = document.getElementById('restorationMessage');
    try {
        const keystoreJSON = await file.text();
        const keystore = JSON.parse(keystoreJSON);
        const password = prompt('Enter the password for your keystore file:');
        if (!password) {
            alert('Password cannot be empty.');
            return null;
        }

        const recoveredPrivateKeyBytes = await recoverPrivateKeyFromKeystore(keystore, password);

        if (recoveredPrivateKeyBytes) {
            const address = await getWalletAddress(recoveredPrivateKeyBytes);
            restorationMessageDiv.textContent = `Wallet restored! Address: ${address}`;
            return { privateKey: recoveredPrivateKeyBytes, address, mnemonic: null };
        } else {
            restorationMessageDiv.textContent = 'Failed to restore wallet. Incorrect password or invalid file.';
            return null;
        }
    } catch (error) {
        console.error('Error restoring from keystore:', error);
        restorationMessageDiv.textContent = 'Error reading or parsing keystore file.';
        return null;
    }
}

async function recoverWalletFromSeed(password) {
      const restorationMessageDiv = document.getElementById('restorationMessage');
    const mnemonic = await recoverSeedPhrase(password);
    if (!mnemonic) {
        restorationMessageDiv.textContent = 'Failed to recover wallet from seed phrase.';
        return null;
    }

    const seed = mnemonicToSeedSync(mnemonic);
    const hdWallet = hdkey.fromMasterSeed(seed);
    const account = hdWallet.derivePath("m/44'/60'/0'/0/0");  //Standard Ethereum derivation path
    const recoveredPrivateKey = account.privateKey;
    const address = await getWalletAddress(recoveredPrivateKey);
    restorationMessageDiv.textContent = `Wallet restored! Address: ${address}`;
    return { privateKey: recoveredPrivateKey, address, mnemonic };
}

// --- UI ---
const keystoreUploadInput = document.getElementById('keystoreUpload');
const restoreFromKeystoreButton = document.getElementById('restoreFromKeystore');
const restoreFromSeedButton = document.getElementById('restoreFromSeed');
const backupButton = document.getElementById('backupButton'); //Get the backup button.

let currentWallet = null; // Store the current wallet object

// --- Event Listeners ---
restoreFromKeystoreButton.addEventListener('click', () => {
    if (keystoreUploadInput.files.length > 0) {
        recoverWalletFromKeystoreFile(keystoreUploadInput.files[0]).then(wallet => {
        if (wallet) {
          currentWallet = wallet;
          //Set current wallet.
          console.log("Wallet after keystore restore", currentWallet);
        }
      });
    } else {
        alert('Please select a keystore file.');
    }
});

restoreFromSeedButton.addEventListener('click', () => {
  const password = prompt('Enter the password used to encrypt your seed phrase:');
  if (!password) {
    alert('Password cannot be empty.');
    return;
  }
  recoverWalletFromSeed(password).then(wallet => {
    if(wallet){
      currentWallet = wallet;
      console.log("Wallet after seed restore", currentWallet);
    }
  });
});

backupButton.addEventListener('click', async () => {
  if (!currentWallet) {
    alert("Please create or restore a wallet before backing up.");
    return;
  }
  const keystoreData = localStorage.getItem(PRIVATE_KEY_STORAGE_KEY);
  if (!keystoreData) {
    alert("No keystore data found.  Ensure wallet is created.");
    return;
  }
  //Simulate download
  const filename = 'keystore.json';
  const json = JSON.stringify({crypto: {
    cipher: 'aes-128-cbc',
    ciphertext: keystoreData,
    cipherparams: {
        iv:  localStorage.getItem('keyIV'),
    },
    kdf: 'pbkdf2',
    kdfparams: {
        salt:  localStorage.getItem(SALT_STORAGE_KEY),
        c: 100000,
        dklen: 16,
        prf: 'hmac-sha256'
    },
    mac: "Not Implemented in this simplified example",
},
version: 3, }, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  alert('Keystore file downloaded. Please store it securely!');

  const mnemonic = await backupWithSeedPhrase();
  if (mnemonic)
  {
     alert(`Seed Phrase: ${mnemonic}.  Backed up and Encrypted.`)
  }
  else{
    alert("Seed phrase backup failed")
  }

});

// --- Initialize Wallet on Load ---
initializeWallet().then(wallet => {
    if (wallet) {
        currentWallet = wallet; // Store the wallet
        // Display address, enable UI, etc.
        console.log('Wallet Initialized:', wallet);
         if (wallet.mnemonic) {
          console.log("mnemonic", wallet.mnemonic)
        }
    } else {
        // Handle initialization failure (e.g., show create/restore options)
        console.log('Wallet initialization failed.');
    }
});


