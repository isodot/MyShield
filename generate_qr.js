const fs = require('fs');
const path = require('path');
const qrcode = require('qrcode');
const address = 'bc1q2fqyukqn4ggvv5qsamhxegrjjzzywpc30hl90r';
const outPath = path.join(__dirname, 'popup', 'donation-qr.png');
qrcode.toFile(outPath, address, { width: 140, margin: 1 }, function (err) {
  if (err) {
    console.error(err);
    process.exit(1);
  }
  console.log('QR image generated:', outPath);
});
