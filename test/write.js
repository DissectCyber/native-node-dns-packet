'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const Packet = require('../packet');

// Modern tap usage: require('tap') and use t.test / t.equal / t.same.
const t = require('tap');

const fixtureDir = path.join(__dirname, 'fixtures');

const files = fs
	.readdirSync(fixtureDir)
	.filter(f => /\.js$/.test(f));

files.forEach(file => {
	t.test('can parse ' + file, t => {
		// Evaluate the fixture JS to a value (same as before), but pass an options object.
		let jsCode = 'foo = ' + fs.readFileSync(path.join(fixtureDir, file), 'utf8');
		const js = vm.runInThisContext(jsCode, { filename: file });

		// new Buffer(size) -> Buffer.alloc(size)
		const buff = Buffer.alloc(4096);

		const written = Packet.write(buff, js);

		const binFile = path.join(fixtureDir, file.replace(/\.js$/, '.bin'));
		const bin = fs.readFileSync(binFile);

		const rtrip = Packet.parse(buff.slice(0, written));

		// t.equal for numbers; t.same for Buffers/objects
		t.equal(written, bin.length, `message length matches for ${file}`);
		t.same(buff.slice(0, written), bin, `binary content matches for ${file}`);
		t.same(rtrip, js, `round-trip object matches for ${file}`);

		t.end();
	});
});
