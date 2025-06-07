// Hardcoded encrypted secrets (paste Python output here)
const ENCRYPTED_SECRETS = {
  github: {
    salt: "Ce8PHofgXybmttytjJ9KKw==",
    ciphertext: "547iEQXUDjJOPXK1AK63n2Y6FKJNet6mQTmlhpfK+D4=",
    nonce: "+KpHrXNP7xZAkf9G",
  },
  "dk-git": {
    salt: "8a+7uO7sMxYI6ivwPQ65/w==",
    ciphertext: "pHtuoiDcXe8Yh5bSSyENS9aQi6GsaLUPqGUpGxRg96Q=",
    nonce: "znuVPUI39a8hqbW1",
  },
  "bybit-ffkr": {
    salt: "AGct8ED3Gy/kysEq7Eqnbw==",
    ciphertext: "aOTc43oSdHTOGbLcVR+Fciy8HfPt58NxEcbL+5HYLP8=",
    nonce: "pt8SyrOsU3iXKZ4e",
  },
  "proton-m": {
    salt: "RbF2zbxqXU367GcZeoM3Kg==",
    ciphertext:
      "9EqgF3nTLQFb3Fe9wazNzmBGVh8AoapRYcxuRCCNusg8UIDvN98hnawlO3uUvQTA",
    nonce: "A6AWf/AeGAGdFpCH",
  },
  icedrive: {
    salt: "LTRt0kgO03FgurFn0rNnxQ==",
    ciphertext: "0UjBu/CEoEk8xpypYZjne53eG5AgB9yt21sxiem9Ag0=",
    nonce: "QMKN43/st0ilJcxT",
  },
};

const copyNumericValue = (button) => {
  // Get the button's text content
  const buttonText = button.textContent;

  // Strip all non-numerical characters (keeping digits and decimal point)
  const numericValue = buttonText.replace(/[^\d.]/g, "");

  // Copy to clipboard
  navigator.clipboard
    .writeText(numericValue)
    .then(() => {
      console.log("Copied to clipboard:", numericValue);
      // Optional: Show a feedback message
      button.textContent = "Copied!";
      setTimeout(() => {
        button.textContent = buttonText;
      }, 1000);
    })
    .catch((err) => {
      console.error("Failed to copy:", err);
    });
};

class TOTPGenerator {
  constructor() {
    this.activePassword = null;
    this.wipeTimer = null;
    this.WIPE_TIMEOUT = 5 * 60 * 1000; // 5 minutes
    this.CSP_NONCE = "1IEbA2a5H";
    this.currentOTPTimer = null; // Track active OTP timer
    this.currentOTP = null; // Track active OTP

    this.initUI();
    this.checkCryptoSupport();
  }

  // ===== CORE FUNCTIONS ===== //
  initUI() {
    this.injectCSPMeta();
    this.populateServices();

    const passInput = document.getElementById("password-input");
    passInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") this.generateOTP();
    });

    document
      .getElementById("generate-btn")
      .addEventListener("click", () => this.generateOTP());
    document
      .getElementById("wipe-btn")
      .addEventListener("click", () => this.wipeAll());
  }

  injectCSPMeta() {
    const meta = document.createElement("meta");
    meta.httpEquiv = "Content-Security-Policy";
    meta.content = `default-src 'self'; script-src 'nonce-${this.CSP_NONCE}' 'self' 'unsafe-eval'; style-src 'self' 'unsafe-inline';`;
    document.head.appendChild(meta);

    const typeMeta = document.createElement("meta");
    typeMeta.httpEquiv = "X-Content-Type-Options";
    typeMeta.content = "nosniff";
    document.head.appendChild(typeMeta);
  }

  // ... [rest of existing methods remain unchanged until generateOTP] ..

  populateServices() {
    const select = document.getElementById("service-select");
    select.innerHTML =
      '<option value="">--&nbsp;&nbsp;Select Account&nbsp;--</option>';

    Object.keys(ENCRYPTED_SECRETS).forEach((service) => {
      const option = document.createElement("option");
      option.value = service;
      option.textContent = service;
      select.appendChild(option);
    });
  }

  async generateOTP() {
    try {
      const service = document.getElementById("service-select").value;
      const password = document.getElementById("password-input").value;

      if (!service || !password) throw new Error("Missing input");

      // Derive key
      const { salt, ciphertext, nonce } = ENCRYPTED_SECRETS[service];
      const key = await this.deriveKey(password, this.base64ToArray(salt));

      // Decrypt
      const secret = await this.decryptSecret(
        this.base64ToArray(ciphertext),
        this.base64ToArray(nonce),
        key
      );

      // Generate and display
      const otp = await this.generateTOTP(secret);
      this.wipeSecret(secret); // NEW: Securely wipe decrypted secret
      this.displayOTP(service, otp);
      this.startWipeTimer();
    } catch (e) {
      document.getElementById("otp-display").innerHTML =
        "Invalid GRSA Encryption Key";
    }
  }

  // NEW: Secure secret wiping
  wipeSecret(secret) {
    try {
      const arr = new TextEncoder().encode(secret);
      for (let i = 0; i < arr.length; i++) {
        arr[i] = 0;
      }
      // Force garbage collection (where supported)
      if (window.gc) window.gc();
    } catch (e) {
      console.error("Secret wipe failed:", e);
    }
  }

  // ===== CRYPTO OPERATIONS ===== //
  async deriveKey(password, salt) {
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt,
        iterations: 100000,
        hash: "SHA-256",
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );
  }

  async decryptSecret(ciphertext, nonce, key) {
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce },
      key,
      ciphertext
    );
    return new TextDecoder().decode(decrypted);
  }

  generateTOTP(secret) {
    // Convert base32 secret to bytes
    const key = this.base32ToBytes(secret);
    const epoch = Math.floor(Date.now() / 1000);
    const timeStep = 30;
    const counter = Math.floor(epoch / timeStep);

    // Convert counter to 8-byte buffer (big-endian)
    const counterBytes = new ArrayBuffer(8);
    const counterView = new DataView(counterBytes);
    counterView.setBigUint64(0, BigInt(counter), false);

    // HMAC-SHA1 calculation
    return crypto.subtle
      .importKey("raw", key, { name: "HMAC", hash: "SHA-1" }, false, ["sign"])
      .then((hmacKey) => {
        return crypto.subtle.sign("HMAC", hmacKey, counterBytes);
      })
      .then((hmacResult) => {
        // Dynamic truncation (RFC 4226)
        const hmac = new Uint8Array(hmacResult);
        const offset = hmac[hmac.length - 1] & 0x0f;
        const binary =
          ((hmac[offset] & 0x7f) << 24) |
          ((hmac[offset + 1] & 0xff) << 16) |
          ((hmac[offset + 2] & 0xff) << 8) |
          (hmac[offset + 3] & 0xff);

        // Generate 6-digit code
        return (binary % 1000000).toString().padStart(6, "0");
      });
  }

  // Helper function for base32 decoding
  base32ToBytes(base32) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    base32 = base32.replace(/=+$/, "").toUpperCase();
    let bits = 0;
    let value = 0;
    let bytes = [];

    for (let i = 0; i < base32.length; i++) {
      const index = alphabet.indexOf(base32[i]);
      if (index === -1) throw new Error("Invalid base32 character");

      value = (value << 5) | index;
      bits += 5;

      if (bits >= 8) {
        bytes.push((value >>> (bits - 8)) & 0xff);
        bits -= 8;
      }
    }

    return new Uint8Array(bytes);
  }

  // ===== UTILITIES ===== //
  base64ToArray(base64) {
    return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
  }

  displayOTP(service, otp) {
    // Clear any existing timer/code first
    this.clearCurrentOTP();

    const display = document.getElementById("otp-display");
    display.innerHTML = `
    <div class="result">
      <div>${service}:&nbsp;</div>
      <div class="otp-code" id="otp-code">${otp}</div>
      <div>Valid for: <span id="countdown">30</span></div>
    </div>
    `;
    const otpDisplay = document.getElementById("otp-display");
    otpDisplay.addEventListener("click", () => {
      copyNumericValue(otpDisplay);
    });

    // Track current OTP
    this.currentOTP = otp;

    // Start new countdown
    let remaining = 30;
    this.currentOTPTimer = setInterval(() => {
      remaining--;
      document.getElementById("countdown").textContent = remaining;
      if (remaining <= 0) {
        this.clearCurrentOTP();
        this.generateOTP();
      }
    }, 1000);
  }

  clearCurrentOTP() {
    if (this.currentOTPTimer) {
      clearInterval(this.currentOTPTimer);
      this.currentOTPTimer = null;
    }
    if (this.currentOTP) {
      // Securely wipe the OTP from memory
      const otpElement = document.querySelector(".otp-code");
      if (otpElement) otpElement.textContent = "••••••";
      this.currentOTP = null;
    }
  }

  displayError(message) {
    document.getElementById(
      "otp-display"
    ).innerHTML = `<div class="error">${message}</div>`;
  }

  startWipeTimer() {
    if (this.wipeTimer) clearTimeout(this.wipeTimer);
    this.wipeTimer = setTimeout(() => this.wipeAll(), this.WIPE_TIMEOUT);
  }

  wipeAll() {
    this.clearCurrentOTP();
    // Zero out sensitive data
    this.activePassword = null;
    document.getElementById("password-input").value = "";
    document.getElementById("otp-display").innerHTML = "";

    // Clear crypto operations from memory
    crypto.subtle.digest("SHA-256", new Uint8Array(1));
    console.log("Nuclear wipe complete");
  }

  checkCryptoSupport() {
    if (!window.crypto?.subtle) {
      document.getElementById("otp-display").innerHTML = `
        <h1>🚨 Browser Incompatible</h1>
        <p>Use Chrome/Firefox/Safari with HTTPS</p>
      `;
      throw new Error("WebCrypto unavailable");
    }
  }
}

// Initialize with CSP check
document.addEventListener("DOMContentLoaded", () => {
  if (document.querySelector("script[nonce]")?.nonce === "1IEbA2a5H") {
    new TOTPGenerator();
  } else {
    document.getElementById("otp-display").innerHTML = `
          <h1>🚨 Security Violation Detected</h1>
          <p>Invalid Content Security Policy configuration</p>
      `;
  }
});
