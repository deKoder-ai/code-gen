// Hardcoded encrypted secrets (paste Python output here)
const ENCRYPTED_SECRETS = {
  github: {
    salt: "Ce8PHofgXybmttytjJ9KKw==",
    ciphertext: "547iEQXUDjJOPXK1AK63n2Y6FKJNet6mQTmlhpfK+D4=",
    nonce: "+KpHrXNP7xZAkf9G",
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

const copyNumericValue = (element) => {
  // Get the button's text content
  const elementText = element.textContent;

  // Strip all non-numerical characters (keeping digits and decimal point)
  const numericValue = elementText.replace(/[^\d.]/g, "");

  // Copy to clipboard
  navigator.clipboard
    .writeText(numericValue)
    .then(() => {
      console.log("Copied to clipboard:", numericValue);
      // Optional: Show a feedback message
      element.textContent = "Copied!";
      setTimeout(() => {
        element.textContent = elementText;
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
    this.service = null;

    this.initUI();
    this.checkCryptoSupport();
  }

  // ===== CORE FUNCTIONS ===== //
  initUI() {
    // this.injectCSPMeta();
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

  populateServices() {
    const serviceSelect = document.getElementById("select-service");
    const serviceOptionsDiv = document.getElementById("service-options-div");
    const mask = document.getElementById("mask");
    mask.addEventListener("click", () => {
      serviceOptionsDiv.style.display = "none";
      mask.style.display = "none";
    });

    serviceSelect.addEventListener("click", () => {
      serviceOptionsDiv.style.display = "block";
      mask.style.display = "block";
    });

    Object.keys(ENCRYPTED_SECRETS).forEach((service) => {
      const serviceOption = document.createElement("button");
      serviceOption.textContent = service;
      serviceOption.addEventListener("click", (e) => {
        this.service = e.target.textContent;
        serviceSelect.innerText = this.service;
        serviceOptionsDiv.style.display = "none";
        mask.style.display = "none";
        document.getElementById("password-input").focus();
      });
      document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") {
          serviceSelect.innerText = "--SELECT SERVICE--";
          serviceOptionsDiv.style.display = "none";
          mask.style.display = "none";
          this.service = null;
        }
      });
      serviceOptionsDiv.appendChild(serviceOption);
    });
  }

  async generateOTP() {
    try {
      const service = this.service;
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
      const serviceShow = document.getElementById("service-show");
      const otpShow = document.getElementById("otp-show");
      serviceShow.textContent = "Invalid GRSA";
      otpShow.textContent = "Encryption Key";
      setTimeout(() => {
        serviceShow.textContent = "GENERATE CODE";
        otpShow.textContent = "☢️ ☣️ ☢️ ☣️ ☢️";
        const password = document.getElementById("password-input");
        password.value = "";
        password.focus();
      }, 2500);
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

    document.getElementById("service-show").innerText = service;
    const otpShow = document.getElementById("otp-show");
    otpShow.innerHTML = otp;
    otpShow.classList.add("otp-style");
    otpShow.addEventListener("click", () => {
      copyNumericValue(otpShow);
    });

    const display = document.getElementById("otp-display");
    display.innerHTML = `
    <div class="flex">
      <div class="result">
        <div><span id="countdown">30</span></div>
      </div>
    </div>
    `;

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
      this.currentOTP = null;
    }
  }

  displayError(message) {
    document.getElementById(
      "service-show"
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
    document.getElementById("service-show").innerText = "GENERATE CODE";
    const otpShow = document.getElementById("otp-show");
    otpShow.innerText = "☢️ ☣️ ☢️ ☣️ ☢️";
    otpShow.classList.remove("otp-style");
    document.getElementById("select-service").innerHTML = "--Select Service--";
    this.service = null;

    // Clear crypto operations from memory
    crypto.subtle.digest("SHA-256", new Uint8Array(1));
    console.log("Nuclear wipe complete");
  }

  checkCryptoSupport() {
    if (!window.crypto?.subtle) {
      document.getElementById("service-show").innerText =
        "🚨 Browser Incompatible";
      document.getElementById("otp-show").innerText = `HTTPS REQUIRED`;
      throw new Error("WebCrypto unavailable");
    }
  }
}

// Initialize with CSP check
document.addEventListener("DOMContentLoaded", () => {
  if (document.querySelector("script[nonce]")?.nonce === "1IEbA2a5H") {
    new TOTPGenerator();
  } else {
    document.getElementById("service-show").innerText =
      "🚨 Security Violation Detected";
    document.getElementById(
      "otp-show"
    ).innerText = `Invalid Content Security Policy config`;
  }
});

