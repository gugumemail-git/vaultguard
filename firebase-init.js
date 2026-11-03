import { initializeApp } from "https://www.gstatic.com/firebasejs/13.1.0/firebase-app.js";
import { getAuth, onAuthStateChanged, createUserWithEmailAndPassword, signInWithEmailAndPassword, signOut } from "https://www.gstatic.com/firebasejs/13.1.0/firebase-auth.js";
import { getFirestore, doc, setDoc, getDoc } from "https://www.gstatic.com/firebasejs/13.1.0/firebase-firestore.js";

const firebaseConfig = {
  apiKey: "AIzaSyBBQFmBvRlqWUvGzPlrCTDNYLVu2LikO0I",
  authDomain: "kelapa-hijau.firebaseapp.com",
  projectId: "kelapa-hijau",
  storageBucket: "kelapa-hijau.firebasestorage.app",
  messagingSenderId: "205794970428",
  appId: "1:205794970428:web:d509f3005977c4c49aac39",
  measurementId: "G-2K2LFL35BX"
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);

// Ekspos ke global window agar bisa diakses dari app.js
window.firebaseAuth = auth;
window.firebaseDb = db;
window.firebaseFunctions = { 
  onAuthStateChanged, 
  createUserWithEmailAndPassword, 
  signInWithEmailAndPassword,
  signOut,
  doc, setDoc, getDoc 
};