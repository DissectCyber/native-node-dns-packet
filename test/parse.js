'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { test } = require('node:test');
const assert = require('node:assert');

const Packet = require('../packet');

const fixtureDir = path.join(__dirname, 'fixtures');

const files = fs.readdirSync(fixtureDir).filter(f => /\.bin$/.test(f));

files.forEach(file => {
	test('can parse ' + file, () => {
		const bin = fs.readFileSync(path.join(fixtureDir, file));
		const jsFile = path.join(fixtureDir, file.replace(/\.bin$/, '.js'));
		const js = vm.runInThisContext('foo = ' + fs.readFileSync(jsFile, 'utf8'), { filename: jsFile });
		const ret = Packet.parse(bin);
		// deepEqual (not strict) so the Packet instance compares structurally
		// against the plain-object fixture without tripping on prototypes.
		assert.deepEqual(ret, js);
	});
});
