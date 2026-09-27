// securerepo:ignore-file - benchmark corpus: looks dangerous to a regex but is safe.
// expect-none: SR-JS-001, SR-JS-002, SR-JS-007, SR-JS-008, SR-JS-009, SR-JS-011
const { exec } = require('child_process');

/*
 * Never call eval(userInput) here.
 * el.innerHTML = userInput is forbidden.
 */
function ui() {
  document.getElementById('status').innerHTML = '';
  document.getElementById('spinner').innerHTML = '<span class="spin"></span>';
  const pattern = /[a-z]+/g;
  const match = pattern.exec(window.title);
  console.log("never use eval(code) with untrusted input");
  exec('git rev-parse HEAD');
  return match;
}

function query(db) {
  return db.query('SELECT * FROM users WHERE active = ?', [true]);
}

// Taint must not leak between functions that reuse short variable names.
function onMessage(msg) {
  const e = JSON.parse(msg.data);
  return e;
}

function schedule(e) {
  setTimeout(() => refresh(e), 500);
  setInterval(function () { poll(e); }, 1000);
  return eval;
}
