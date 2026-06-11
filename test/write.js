'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { test } = require('node:test');
const assert = require('node:assert');

const Packet = require('../packet');

const fixtureDir = path.join(__dirname, 'fixtures');

const files = fs.readdirSync(fixtureDir).filter(f => /\.js$/.test(f));

files.forEach(file => {
	test('can write ' + file, () => {
		const js = vm.runInThisContext('foo = ' + fs.readFileSync(path.join(fixtureDir, file), 'utf8'), { filename: file });

		const buff = Buffer.alloc(4096);
		const written = Packet.write(buff, js);

		const binFile = path.join(fixtureDir, file.replace(/\.js$/, '.bin'));
		const bin = fs.readFileSync(binFile);

		const rtrip = Packet.parse(buff.slice(0, written));

		assert.strictEqual(written, bin.length, `message length matches for ${file}`);
		assert.deepEqual(buff.slice(0, written), bin, `binary content matches for ${file}`);
		assert.deepEqual(rtrip, js, `round-trip object matches for ${file}`);
	});
});
