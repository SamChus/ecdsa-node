import React, { useState } from "react";
import { keccak256 } from "ethereum-cryptography/keccak";
import { utf8ToBytes, toHex } from "ethereum-cryptography/utils";
import { secp256k1 } from "ethereum-cryptography/secp256k1";

const Register = () => {
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const hashPassword = async (password) => {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(hashBuffer))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  };

  // const hashPassword = async (password) => {
  //     const passwordBytes = utf8ToBytes(password);
  //     const hash = keccak256(passwordBytes);
  //     return Array.from(hash)
  //         .map((b) => b.toString(16).padStart(2, "0"))
  //         .join("");
  // };

  // const decryptPassword = async (hashedPassword) => {
  //     // Note: Hashing is a one-way function and cannot be reversed.
  //     // Decryption is not possible for hashed passwords.
  //     // If you need to verify a password, compare the hash of the input password with the stored hash.
  //     throw new Error("Decryption of hashed passwords is not possible.");
  // };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (password !== confirmPassword) {
      setError("Passwords do not match!");
      setSuccess("");
    } else {
      setError("");

      const hashedPassword = await hashPassword(password);

      const auth = localStorage.getItem("hashedPassword");

      // Store the hashed password securely (example using localStorage)
      if (!auth) {
        localStorage.setItem("hashedPassword", hashedPassword);
        const privateKey = await generatePrivateKey();
        const publicKey = await generatePublicKey(privateKey);
        localStorage.setItem("privateKey", privateKey);
        localStorage.setItem("publicKey", publicKey);
        setSuccess("Registration successful!");
        setPassword("");
        setConfirmPassword("");
      } else {
        // Check if the hashed password already exists in localStorage
        const existingHashedPassword = localStorage.getItem("hashedPassword");
        if (existingHashedPassword === hashedPassword) {
          setError("");
          setSuccess("You are Logged In!");
          setPassword("");
          setConfirmPassword("");
        } else {
          setError("User does'nt exist!");
          setSuccess("");
        }
      }
    }
  };

  const generatePrivateKey = async () => {
    const privateKey = secp256k1.utils.randomPrivateKey();
    const privateKeyHex = toHex(privateKey);
    return privateKeyHex;
  };

  const generatePublicKey = async (privateKey) => {
    const privateKeyBytes = Uint8Array.from(Buffer.from(privateKey, "hex"));
    const publicKey = secp256k1.getPublicKey(privateKeyBytes);

    const publicKeyHex = toHex(publicKey);
    console.log("Public Key:", publicKeyHex);
    const address = await ethereumAddress(publicKeyHex);
    console.log("Ethereum Address:", address);
    localStorage.setItem("address", address);
    return publicKeyHex;
  };

  const ethereumAddress = async (publicKeyHex) => {
    const publicKeyBytes = Uint8Array.from(Buffer.from(publicKeyHex, "hex"));
    const address = keccak256(publicKeyBytes).slice(-20); 
    const addressHex = "0x" + toHex(address).toUpperCase();
    return addressHex;
  }

  return (
    <div className="register-container">
      <form className="register-form" onSubmit={handleSubmit}>
        <h2>Auth</h2>
        <div className="form-group">
          <label htmlFor="password">Password</label>
          <input
            type="password"
            id="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </div>
        <div className="form-group">
          <label htmlFor="confirmPassword">Confirm Password</label>
          <input
            type="password"
            id="confirmPassword"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            required
          />
        </div>
        {error && <p className="error">{error}</p>}
        {success && <p className="success">{success}</p>}
        <button type="submit">Register</button>
      </form>
    </div>
  );
};

export default Register;
