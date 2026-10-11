const { exec } = require('child_process');
const express = require('express');
const app = express();

app.get('/ping', (req, res) => {
  const host = req.query.host;
  exec('ping -c 1 ' + host); // expect: SR-JS-008
  const id = req.params.id;
  db.query('SELECT * FROM users WHERE id = ' + id); // expect: SR-JS-011
  res.redirect(req.query.next); // expect: SR-JS-018
  res.send('<p>' + req.query.name + '</p>'); // expect: SR-JS-023
});

app.get('/file', (req, res) => {
  const name = req.query.file;
  res.sendFile(name); // expect: SR-JS-016
});

function render() {
  const fragment = location.hash.slice(1);
  document.getElementById('out').innerHTML = fragment; // expect: SR-JS-002
  eval(fragment); // expect: SR-JS-001
}
