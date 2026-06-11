// Copyright 2011 Timothy J Fontaine <tjfontaine@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the 'Software'), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE

// TODO: change the default UDP packet size that node-dns sends
//       from 4096 to conform to these:
//       - [requestor's payload size](https://tools.ietf.org/html/rfc6891#section-6.2.3)
//       - [responders's payload size](https://tools.ietf.org/html/rfc6891#section-6.2.4)

'use strict';

var consts = require('./consts'),
    BufferCursor = require('./buffercursor'),
    BufferCursorOverflow = BufferCursor.BufferCursorOverflow,
    assert = require('assert');

function assertUndefined(val, msg) {
  assert(typeof val != 'undefined', msg);
}

var Packet = module.exports = function() {
  this.header = {
    id: 0,
    qr: 0,
    opcode: 0,
    aa: 0,
    tc: 0,
    rd: 1,
    ra: 0,
    res1: 0,
    res2: 0,
    res3: 0,
    rcode: 0
  };
  this.question = [];
  this.answer = [];
  this.authority = [];
  this.additional = [];
  this.edns_options = [];   // TODO: DEPRECATED! Use `.edns.options` instead!
  this.payload = undefined; // TODO: DEPRECATED! Use `.edns.payload` instead!
};

var LABEL_POINTER = 0xC0;

var isPointer = function(len) {
  return (len & LABEL_POINTER) === LABEL_POINTER;
};

function nameUnpack(buff) {
  var len, comp, end, pos, part, combine = '';

  len = buff.readUInt8();
  comp = false;
  end = buff.tell();

  while (len !== 0) {
    if (isPointer(len)) {
      len -= LABEL_POINTER;
      len = len << 8;
      pos = len + buff.readUInt8();
      if (!comp)
        end = buff.tell();
      buff.seek(pos);
      len = buff.readUInt8();
      comp = true;
      continue;
    }

    part = buff.toString('ascii', len);

    if (combine.length)
      combine = combine + '.' + part;
    else
      combine = part;

    len = buff.readUInt8();

    if (!comp)
      end = buff.tell();
  }

  buff.seek(end);

  return combine;
}

function namePack(str, buff, index) {
  var offset, dot, part;

  while (str) {
    if (index[str]) {
      offset = (LABEL_POINTER << 8) + index[str];
      buff.writeUInt16BE(offset);
      break;
    } else {
      index[str] = buff.tell();
      dot = str.indexOf('.');
      if (dot > -1) {
        part = str.slice(0, dot);
        str = str.slice(dot + 1);
      } else {
        part = str;
        str = undefined;
      }
      buff.writeUInt8(part.length);
      buff.write(part, part.length, 'ascii');
    }
  }

  if (!str) {
    buff.writeUInt8(0);
  }
}

// Write a domain name with full labels only -- no compression pointers, and
// without registering its labels as future compression targets. Required for
// RDATA whose names must not be compressed, e.g. the SRV target (RFC 2782).
function namePackUncompressed(str, buff) {
  var dot, part;

  while (str) {
    dot = str.indexOf('.');
    if (dot > -1) {
      part = str.slice(0, dot);
      str = str.slice(dot + 1);
    } else {
      part = str;
      str = undefined;
    }
    buff.writeUInt8(part.length);
    buff.write(part, part.length, 'ascii');
  }

  buff.writeUInt8(0);
}

var
  WRITE_HEADER              = 100001,
  WRITE_TRUNCATE            = 100002,
  WRITE_QUESTION            = 100003,
  WRITE_RESOURCE_RECORD     = 100004,
  WRITE_RESOURCE_WRITE      = 100005,
  WRITE_RESOURCE_DONE       = 100006,
  WRITE_RESOURCE_END        = 100007,
  WRITE_EDNS                = 100008,
  WRITE_END                 = 100009,
  WRITE_A     = consts.NAME_TO_QTYPE.A,
  WRITE_AAAA  = consts.NAME_TO_QTYPE.AAAA,
  WRITE_NS    = consts.NAME_TO_QTYPE.NS,
  WRITE_CNAME = consts.NAME_TO_QTYPE.CNAME,
  WRITE_PTR   = consts.NAME_TO_QTYPE.PTR,
  WRITE_SPF   = consts.NAME_TO_QTYPE.SPF,
  WRITE_MX    = consts.NAME_TO_QTYPE.MX,
  WRITE_SRV   = consts.NAME_TO_QTYPE.SRV,
  WRITE_TXT   = consts.NAME_TO_QTYPE.TXT,
  WRITE_SOA   = consts.NAME_TO_QTYPE.SOA,
  WRITE_CAA   = consts.NAME_TO_QTYPE.CAA,
  WRITE_OPT   = consts.NAME_TO_QTYPE.OPT,
  WRITE_NAPTR = consts.NAME_TO_QTYPE.NAPTR,
  WRITE_TLSA  = consts.NAME_TO_QTYPE.TLSA,
  WRITE_DNAME = consts.NAME_TO_QTYPE.DNAME,
  WRITE_DS         = consts.NAME_TO_QTYPE.DS,
  WRITE_CDS        = consts.NAME_TO_QTYPE.CDS,
  WRITE_DNSKEY     = consts.NAME_TO_QTYPE.DNSKEY,
  WRITE_RRSIG      = consts.NAME_TO_QTYPE.RRSIG,
  WRITE_NSEC       = consts.NAME_TO_QTYPE.NSEC,
  WRITE_NSEC3      = consts.NAME_TO_QTYPE.NSEC3,
  WRITE_NSEC3PARAM = consts.NAME_TO_QTYPE.NSEC3PARAM,
  WRITE_SSHFP      = consts.NAME_TO_QTYPE.SSHFP,
  WRITE_SMIMEA     = consts.NAME_TO_QTYPE.SMIMEA,
  WRITE_CERT       = consts.NAME_TO_QTYPE.CERT,
  WRITE_DHCID      = consts.NAME_TO_QTYPE.DHCID,
  WRITE_OPENPGPKEY = consts.NAME_TO_QTYPE.OPENPGPKEY,
  WRITE_IPSECKEY   = consts.NAME_TO_QTYPE.IPSECKEY,
  WRITE_URI        = consts.NAME_TO_QTYPE.URI,
  WRITE_LOC        = consts.NAME_TO_QTYPE.LOC,
  WRITE_CSYNC      = consts.NAME_TO_QTYPE.CSYNC,
  WRITE_ZONEMD     = consts.NAME_TO_QTYPE.ZONEMD,
  WRITE_SVCB       = consts.NAME_TO_QTYPE.SVCB,
  WRITE_HTTPS      = consts.NAME_TO_QTYPE.HTTPS;

function writeHeader(buff, packet) {
  assert(packet.header, 'Packet requires "header"');
  buff.writeUInt16BE(packet.header.id & 0xFFFF);
  var val = 0;
  val += (packet.header.qr << 15) & 0x8000;
  val += (packet.header.opcode << 11) & 0x7800;
  val += (packet.header.aa << 10) & 0x400;
  val += (packet.header.tc << 9) & 0x200;
  val += (packet.header.rd << 8) & 0x100;
  val += (packet.header.ra << 7) & 0x80;
  val += (packet.header.res1 << 6) & 0x40;
  val += (packet.header.res2 << 5) & 0x20;
  val += (packet.header.res3 << 4) & 0x10;
  val += packet.header.rcode & 0xF;
  buff.writeUInt16BE(val & 0xFFFF);
  assert(packet.question.length == 1, 'DNS requires one question');
  // aren't used
  buff.writeUInt16BE(1);
  // answer offset 6
  buff.writeUInt16BE(packet.answer.length & 0xFFFF);
  // authority offset 8
  buff.writeUInt16BE(packet.authority.length & 0xFFFF);
  // additional offset 10
  buff.writeUInt16BE(packet.additional.length & 0xFFFF);
  return WRITE_QUESTION;
}

function writeTruncate(buff, packet, section, val) {
  // From here to the "return" statement is a temporary patch that suffices
  // until the "XXX FIXME TODO" issue below is fixed.  When that's fixed,
  // remove these lines.
  //
  // The RFC says that when the UDP response overflows, we should start
  // dropping sections, starting from the end section (which may be
  // optional info), until it fits, then set the TC bit if we've dropped
  // essential data.  However, the code below that tries to match the RFC's
  // requirements is incomplete and throws an exception.
  //
  // Well-behaved clients retry via TCP when they see the TC bit.  So a
  // quick-and-dirty approach is to recreate the buffer, and write a new
  // copy of the header with the TC bit set, and then end the response.
  // This allows well-behaved clients to carry on and retry with TCP.
  //
  // Yes, there will be circumstances where the essential response data
  // would fit and we could have dropped the optional response data, saving
  // the retry.  But, until this code is properly fixed, it's much better
  // to respond a bit inefficiently instead of leaving the client hanging
  // with no response at all.
  buff = new BufferCursor(buff.buffer);
  writeHeader(buff, packet);
  const savedPosition = buff.tell();
  buff.seek(2);
  val = buff.readUInt16BE();
  val |= (1 << 9) & 0x200;
  buff.seek(2);
  buff.writeUInt16BE(val);
  buff.seek(savedPosition);
  return WRITE_END;

  // XXX FIXME TODO truncation is currently done wrong.
  // Quote rfc2181 section 9
  // The TC bit should not be set merely because some extra information
  // could have been included, but there was insufficient room.  This
  // includes the results of additional section processing.  In such cases
  // the entire RRSet that will not fit in the response should be omitted,
  // and the reply sent as is, with the TC bit clear.  If the recipient of
  // the reply needs the omitted data, it can construct a query for that
  // data and send that separately.
  //
  // TODO IOW only set TC if we hit it in ANSWERS otherwise make sure an
  // entire RRSet is removed during a truncation.
  var pos;

  buff.seek(2);
  val = buff.readUInt16BE();
  val |= (1 << 9) & 0x200;
  buff.seek(2);
  buff.writeUInt16BE(val);
  switch (section) {
    case 'answer':
      pos = 6;
      // seek to authority and clear it and additional out
      buff.seek(8);
      buff.writeUInt16BE(0);
      buff.writeUInt16BE(0);
      break;
    case 'authority':
      pos = 8;
      // seek to additional and clear it out
      buff.seek(10);
      buff.writeUInt16BE(0);
      break;
    case 'additional':
      pos = 10;
      break;
  }
  buff.seek(pos);
  buff.writeUInt16BE(count - 1); // TODO: count not defined!
  buff.seek(last_resource);      // TODO: last_resource not defined!
  return WRITE_END;
}

function writeQuestion(buff, val, label_index) {
  assert(val, 'Packet requires a question');
  assertUndefined(val.name, 'Question requires a "name"');
  assertUndefined(val.type, 'Question requires a "type"');
  assertUndefined(val.class, 'Questionn requires a "class"');
  namePack(val.name, buff, label_index);
  buff.writeUInt16BE(val.type & 0xFFFF);
  buff.writeUInt16BE(val.class & 0xFFFF);
  return WRITE_RESOURCE_RECORD;
}

function writeResource(buff, val, label_index, rdata) {
  assert(val, 'Resource must be defined');
  assertUndefined(val.name, 'Resource record requires "name"');
  assertUndefined(val.type, 'Resource record requires "type"');
  assertUndefined(val.class, 'Resource record requires "class"');
  assertUndefined(val.ttl, 'Resource record requires "ttl"');
  namePack(val.name, buff, label_index);
  buff.writeUInt16BE(val.type & 0xFFFF);
  buff.writeUInt16BE(val.class & 0xFFFF);
  buff.writeUInt32BE(val.ttl & 0xFFFFFFFF);
  rdata.pos = buff.tell();
  buff.writeUInt16BE(0); // if there is rdata, then this value will be updated
                         // to the correct value by 'writeResourceDone'
  return val.type;
}

function writeResourceDone(buff, rdata) {
  var pos = buff.tell();
  buff.seek(rdata.pos);
  buff.writeUInt16BE(pos - rdata.pos - 2);
  buff.seek(pos);
  return WRITE_RESOURCE_RECORD;
}

// Inverse of ipToByteArray: format a 4-byte buffer as dotted IPv4.
function ipv4FromBytes(buf) {
  return buf[0] + '.' + buf[1] + '.' + buf[2] + '.' + buf[3];
}

// Format a 16-byte buffer as IPv6 in the same (non-zero-compressed) form that
// parseAAAA produces, so it round-trips through ipToByteArray.
function ipv6FromBytes(buf) {
  var groups = [];
  for (var i = 0; i < 16; i += 2) {
    groups.push(((buf[i] << 8) | buf[i + 1]).toString(16));
  }
  return groups.join(':');
}

// Parse an IPv4 or IPv6 address string into its network-order byte array
// (4 bytes for IPv4, 16 for IPv6). Replaces the former ipaddr.js dependency.
function ipToByteArray(address) {
  if (address.indexOf(':') === -1) {
    return parseIPv4(address);
  }
  return parseIPv6(address);
}

function parseIPv4(address) {
  var parts = address.split('.');
  assert(parts.length === 4, 'Invalid IPv4 address: ' + address);
  return parts.map(function(part) {
    var byte = parseInt(part, 10);
    assert(/^\d+$/.test(part) && byte >= 0 && byte <= 255,
      'Invalid IPv4 address: ' + address);
    return byte;
  });
}

function parseIPv6(address) {
  // Split into the part before and after the "::" zero-compression marker.
  var halves = address.split('::');
  assert(halves.length <= 2, 'Invalid IPv6 address: ' + address);

  function expand(group) {
    if (group === '') return [];
    return group.split(':');
  }

  var head = expand(halves[0]);
  var tail = halves.length === 2 ? expand(halves[1]) : [];

  // A trailing dotted-quad (e.g. "::ffff:1.2.3.4") contributes two 16-bit
  // groups; pull it off the end and convert.
  var trailer = [];
  var combined = head.concat(tail);
  var last = combined[combined.length - 1];
  if (last !== undefined && last.indexOf('.') !== -1) {
    var v4 = parseIPv4(last);
    trailer = [
      ((v4[0] << 8) | v4[1]).toString(16),
      ((v4[2] << 8) | v4[3]).toString(16)
    ];
    if (tail.length) {
      tail = tail.slice(0, -1).concat(trailer);
    } else {
      head = head.slice(0, -1).concat(trailer);
    }
  }

  var groups;
  if (halves.length === 2) {
    var fill = 8 - (head.length + tail.length);
    assert(fill >= 1, 'Invalid IPv6 address: ' + address);
    groups = head.concat(new Array(fill).fill('0'), tail);
  } else {
    groups = head;
  }

  assert(groups.length === 8, 'Invalid IPv6 address: ' + address);

  var bytes = [];
  groups.forEach(function(group) {
    assert(/^[0-9a-fA-F]{1,4}$/.test(group), 'Invalid IPv6 address: ' + address);
    var word = parseInt(group, 16);
    bytes.push((word >> 8) & 0xFF, word & 0xFF);
  });
  return bytes;
}

function writeIp(buff, val) {
  //TODO XXX FIXME -- assert that address is of proper type
  assertUndefined(val.address, 'A/AAAA record requires "address"');
  val = ipToByteArray(val.address);
  val.forEach(function(b) {
    buff.writeUInt8(b);
  });
  return WRITE_RESOURCE_DONE;
}

function writeCname(buff, val, label_index) {
  assertUndefined(val.data, 'NS/CNAME/PTR record requires "data"');
  namePack(val.data, buff, label_index);
  return WRITE_RESOURCE_DONE;
}

// DNAME shares CNAME's shape (a single <domain-name> in `data`), but its
// target MUST NOT be compressed (RFC 6672 section 2.1 / RFC 3597 section 4).
function writeDname(buff, val) {
  assertUndefined(val.data, 'DNAME record requires "data"');
  namePackUncompressed(val.data, buff);
  return WRITE_RESOURCE_DONE;
}

// For <character-string> see: http://tools.ietf.org/html/rfc1035#section-3.3
// For TXT: http://tools.ietf.org/html/rfc1035#section-3.3.14
function writeTxt(buff, val) {
  //TODO XXX FIXME -- split on max char string and loop
  assertUndefined(val.data, 'TXT record requires "data"');
  for (var i=0,len=val.data.length; i<len; i++) {
    var dataLen = Buffer.byteLength(val.data[i], 'utf8');
    buff.writeUInt8(dataLen);
    buff.write(val.data[i], dataLen, 'utf8');
  }
  return WRITE_RESOURCE_DONE;
}

// For CAA: https://www.rfc-editor.org/rfc/rfc8659#section-4.1
function writeCaa(buff, val) {
  assertUndefined(val.flags, 'CAA record requires "flags"');
  assertUndefined(val.data, 'CAA record requires "data"');
  assertUndefined(val.tag, 'CAA record requires "tag"');
  var dataLen = Buffer.byteLength(val.tag, 'utf8');
  buff.writeUInt8(val.flags);
  buff.writeUInt8(dataLen);
  buff.write(val.tag, dataLen, 'utf8');
  buff.write(val.data, 'utf8');
  return WRITE_RESOURCE_DONE;
}

function writeMx(buff, val, label_index) {
  assertUndefined(val.priority, 'MX record requires "priority"');
  assertUndefined(val.exchange, 'MX record requires "exchange"');
  buff.writeUInt16BE(val.priority & 0xFFFF);
  namePack(val.exchange, buff, label_index);
  return WRITE_RESOURCE_DONE;
}

// SRV: https://tools.ietf.org/html/rfc2782
function writeSrv(buff, val, label_index) {
  assertUndefined(val.priority, 'SRV record requires "priority"');
  assertUndefined(val.weight, 'SRV record requires "weight"');
  assertUndefined(val.port, 'SRV record requires "port"');
  assertUndefined(val.target, 'SRV record requires "target"');
  buff.writeUInt16BE(val.priority & 0xFFFF);
  buff.writeUInt16BE(val.weight & 0xFFFF);
  buff.writeUInt16BE(val.port & 0xFFFF);
  // SRV targets MUST NOT be compressed (RFC 2782).
  namePackUncompressed(val.target, buff);
  return WRITE_RESOURCE_DONE;
}

function writeSoa(buff, val, label_index) {
  assertUndefined(val.primary, 'SOA record requires "primary"');
  assertUndefined(val.admin, 'SOA record requires "admin"');
  assertUndefined(val.serial, 'SOA record requires "serial"');
  assertUndefined(val.refresh, 'SOA record requires "refresh"');
  assertUndefined(val.retry, 'SOA record requires "retry"');
  assertUndefined(val.expiration, 'SOA record requires "expiration"');
  assertUndefined(val.minimum, 'SOA record requires "minimum"');
  namePack(val.primary, buff, label_index);
  namePack(val.admin, buff, label_index);
  buff.writeUInt32BE(val.serial & 0xFFFFFFFF);
  buff.writeInt32BE(val.refresh & 0xFFFFFFFF);
  buff.writeInt32BE(val.retry & 0xFFFFFFFF);
  buff.writeInt32BE(val.expiration & 0xFFFFFFFF);
  buff.writeInt32BE(val.minimum & 0xFFFFFFFF);
  return WRITE_RESOURCE_DONE;
}

// http://tools.ietf.org/html/rfc3403#section-4.1
function writeNaptr(buff, val, label_index) {
  assertUndefined(val.order, 'NAPTR record requires "order"');
  assertUndefined(val.preference, 'NAPTR record requires "preference"');
  assertUndefined(val.flags, 'NAPTR record requires "flags"');
  assertUndefined(val.service, 'NAPTR record requires "service"');
  assertUndefined(val.regexp, 'NAPTR record requires "regexp"');
  assertUndefined(val.replacement, 'NAPTR record requires "replacement"');
  buff.writeUInt16BE(val.order & 0xFFFF);
  buff.writeUInt16BE(val.preference & 0xFFFF);
  buff.writeUInt8(val.flags.length);
  buff.write(val.flags, val.flags.length, 'ascii');
  buff.writeUInt8(val.service.length);
  buff.write(val.service, val.service.length, 'ascii');
  buff.writeUInt8(val.regexp.length);
  buff.write(val.regexp, val.regexp.length, 'ascii');
  // NAPTR replacement names MUST NOT be compressed (RFC 3597 section 4).
  namePackUncompressed(val.replacement, buff);
  return WRITE_RESOURCE_DONE;
}

// https://tools.ietf.org/html/rfc6698
function writeTlsa(buff, val) {
  assertUndefined(val.usage, 'TLSA record requires "usage"');
  assertUndefined(val.selector, 'TLSA record requires "selector"');
  assertUndefined(val.matchingtype, 'TLSA record requires "matchingtype"');
  assertUndefined(val.buff, 'TLSA record requires "buff"');
  buff.writeUInt8(val.usage);
  buff.writeUInt8(val.selector);
  buff.writeUInt8(val.matchingtype);
  buff.copy(val.buff);
  return WRITE_RESOURCE_DONE;
}

// DS (RFC 4034 section 5.1) and CDS (RFC 7344) share this layout.
function writeDs(buff, val) {
  assertUndefined(val.key_tag, 'DS record requires "key_tag"');
  assertUndefined(val.algorithm, 'DS record requires "algorithm"');
  assertUndefined(val.digest_type, 'DS record requires "digest_type"');
  assertUndefined(val.digest, 'DS record requires "digest"');
  buff.writeUInt16BE(val.key_tag & 0xFFFF);
  buff.writeUInt8(val.algorithm);
  buff.writeUInt8(val.digest_type);
  buff.copy(val.digest);
  return WRITE_RESOURCE_DONE;
}

// DNSKEY (RFC 4034 section 2.1).
function writeDnskey(buff, val) {
  assertUndefined(val.flags, 'DNSKEY record requires "flags"');
  assertUndefined(val.protocol, 'DNSKEY record requires "protocol"');
  assertUndefined(val.algorithm, 'DNSKEY record requires "algorithm"');
  assertUndefined(val.public_key, 'DNSKEY record requires "public_key"');
  buff.writeUInt16BE(val.flags & 0xFFFF);
  buff.writeUInt8(val.protocol);
  buff.writeUInt8(val.algorithm);
  buff.copy(val.public_key);
  return WRITE_RESOURCE_DONE;
}

// RRSIG (RFC 4034 section 3.1). The signer name is not compressed.
function writeRrsig(buff, val) {
  assertUndefined(val.type_covered, 'RRSIG record requires "type_covered"');
  assertUndefined(val.algorithm, 'RRSIG record requires "algorithm"');
  assertUndefined(val.labels, 'RRSIG record requires "labels"');
  assertUndefined(val.original_ttl, 'RRSIG record requires "original_ttl"');
  assertUndefined(val.expiration, 'RRSIG record requires "expiration"');
  assertUndefined(val.inception, 'RRSIG record requires "inception"');
  assertUndefined(val.key_tag, 'RRSIG record requires "key_tag"');
  assertUndefined(val.signer, 'RRSIG record requires "signer"');
  assertUndefined(val.signature, 'RRSIG record requires "signature"');
  buff.writeUInt16BE(val.type_covered & 0xFFFF);
  buff.writeUInt8(val.algorithm);
  buff.writeUInt8(val.labels);
  buff.writeUInt32BE(val.original_ttl >>> 0);
  buff.writeUInt32BE(val.expiration >>> 0);
  buff.writeUInt32BE(val.inception >>> 0);
  buff.writeUInt16BE(val.key_tag & 0xFFFF);
  namePackUncompressed(val.signer, buff);
  buff.copy(val.signature);
  return WRITE_RESOURCE_DONE;
}

// NSEC (RFC 4034 section 4.1). The next domain name is not compressed; the
// type bit maps are kept as raw bytes.
function writeNsec(buff, val) {
  assertUndefined(val.next_domain, 'NSEC record requires "next_domain"');
  assertUndefined(val.type_bitmap, 'NSEC record requires "type_bitmap"');
  namePackUncompressed(val.next_domain, buff);
  buff.copy(val.type_bitmap);
  return WRITE_RESOURCE_DONE;
}

// NSEC3 (RFC 5155 section 3.2).
function writeNsec3(buff, val) {
  assertUndefined(val.hash_algorithm, 'NSEC3 record requires "hash_algorithm"');
  assertUndefined(val.flags, 'NSEC3 record requires "flags"');
  assertUndefined(val.iterations, 'NSEC3 record requires "iterations"');
  assertUndefined(val.salt, 'NSEC3 record requires "salt"');
  assertUndefined(val.next_hashed_owner, 'NSEC3 record requires "next_hashed_owner"');
  assertUndefined(val.type_bitmap, 'NSEC3 record requires "type_bitmap"');
  buff.writeUInt8(val.hash_algorithm);
  buff.writeUInt8(val.flags);
  buff.writeUInt16BE(val.iterations & 0xFFFF);
  buff.writeUInt8(val.salt.length);
  buff.copy(val.salt);
  buff.writeUInt8(val.next_hashed_owner.length);
  buff.copy(val.next_hashed_owner);
  buff.copy(val.type_bitmap);
  return WRITE_RESOURCE_DONE;
}

// NSEC3PARAM (RFC 5155 section 4.2).
function writeNsec3param(buff, val) {
  assertUndefined(val.hash_algorithm, 'NSEC3PARAM record requires "hash_algorithm"');
  assertUndefined(val.flags, 'NSEC3PARAM record requires "flags"');
  assertUndefined(val.iterations, 'NSEC3PARAM record requires "iterations"');
  assertUndefined(val.salt, 'NSEC3PARAM record requires "salt"');
  buff.writeUInt8(val.hash_algorithm);
  buff.writeUInt8(val.flags);
  buff.writeUInt16BE(val.iterations & 0xFFFF);
  buff.writeUInt8(val.salt.length);
  buff.copy(val.salt);
  return WRITE_RESOURCE_DONE;
}

// SSHFP (RFC 4255 section 3.1).
function writeSshfp(buff, val) {
  assertUndefined(val.algorithm, 'SSHFP record requires "algorithm"');
  assertUndefined(val.fptype, 'SSHFP record requires "fptype"');
  assertUndefined(val.fingerprint, 'SSHFP record requires "fingerprint"');
  buff.writeUInt8(val.algorithm);
  buff.writeUInt8(val.fptype);
  buff.copy(val.fingerprint);
  return WRITE_RESOURCE_DONE;
}

// CERT (RFC 4398 section 2).
function writeCert(buff, val) {
  assertUndefined(val.cert_type, 'CERT record requires "cert_type"');
  assertUndefined(val.key_tag, 'CERT record requires "key_tag"');
  assertUndefined(val.algorithm, 'CERT record requires "algorithm"');
  assertUndefined(val.certificate, 'CERT record requires "certificate"');
  buff.writeUInt16BE(val.cert_type & 0xFFFF);
  buff.writeUInt16BE(val.key_tag & 0xFFFF);
  buff.writeUInt8(val.algorithm);
  buff.copy(val.certificate);
  return WRITE_RESOURCE_DONE;
}

// DHCID (RFC 4701) -- the RDATA is a single opaque blob.
function writeDhcid(buff, val) {
  assertUndefined(val.data, 'DHCID record requires "data"');
  buff.copy(val.data);
  return WRITE_RESOURCE_DONE;
}

// OPENPGPKEY (RFC 7929) -- a single opaque public key blob.
function writeOpenpgpkey(buff, val) {
  assertUndefined(val.public_key, 'OPENPGPKEY record requires "public_key"');
  buff.copy(val.public_key);
  return WRITE_RESOURCE_DONE;
}

// IPSECKEY (RFC 4025 section 2). Gateway encoding depends on gateway_type:
// 0 = none, 1 = IPv4, 2 = IPv6, 3 = uncompressed domain name.
function writeIpseckey(buff, val) {
  assertUndefined(val.precedence, 'IPSECKEY record requires "precedence"');
  assertUndefined(val.gateway_type, 'IPSECKEY record requires "gateway_type"');
  assertUndefined(val.algorithm, 'IPSECKEY record requires "algorithm"');
  assertUndefined(val.public_key, 'IPSECKEY record requires "public_key"');
  buff.writeUInt8(val.precedence);
  buff.writeUInt8(val.gateway_type);
  buff.writeUInt8(val.algorithm);
  switch (val.gateway_type) {
    case 0:
      break;
    case 1:
    case 2:
      ipToByteArray(val.gateway).forEach(function(b) { buff.writeUInt8(b); });
      break;
    case 3:
      namePackUncompressed(val.gateway, buff);
      break;
    default:
      throw new Error('IPSECKEY unknown gateway_type: ' + val.gateway_type);
  }
  buff.copy(val.public_key);
  return WRITE_RESOURCE_DONE;
}

// URI (RFC 7553). Target is the remaining RDATA as text (no length prefix).
function writeUri(buff, val) {
  assertUndefined(val.priority, 'URI record requires "priority"');
  assertUndefined(val.weight, 'URI record requires "weight"');
  assertUndefined(val.target, 'URI record requires "target"');
  buff.writeUInt16BE(val.priority & 0xFFFF);
  buff.writeUInt16BE(val.weight & 0xFFFF);
  buff.write(val.target, Buffer.byteLength(val.target, 'utf8'), 'utf8');
  return WRITE_RESOURCE_DONE;
}

// LOC (RFC 1876 section 2). size/precision/lat/long/altitude are kept in their
// raw wire-encoded form.
function writeLoc(buff, val) {
  assertUndefined(val.version, 'LOC record requires "version"');
  assertUndefined(val.size, 'LOC record requires "size"');
  assertUndefined(val.horizontal_precision, 'LOC record requires "horizontal_precision"');
  assertUndefined(val.vertical_precision, 'LOC record requires "vertical_precision"');
  assertUndefined(val.latitude, 'LOC record requires "latitude"');
  assertUndefined(val.longitude, 'LOC record requires "longitude"');
  assertUndefined(val.altitude, 'LOC record requires "altitude"');
  buff.writeUInt8(val.version);
  buff.writeUInt8(val.size);
  buff.writeUInt8(val.horizontal_precision);
  buff.writeUInt8(val.vertical_precision);
  buff.writeUInt32BE(val.latitude >>> 0);
  buff.writeUInt32BE(val.longitude >>> 0);
  buff.writeUInt32BE(val.altitude >>> 0);
  return WRITE_RESOURCE_DONE;
}

// CSYNC (RFC 7477 section 2.1).
function writeCsync(buff, val) {
  assertUndefined(val.serial, 'CSYNC record requires "serial"');
  assertUndefined(val.flags, 'CSYNC record requires "flags"');
  assertUndefined(val.type_bitmap, 'CSYNC record requires "type_bitmap"');
  buff.writeUInt32BE(val.serial >>> 0);
  buff.writeUInt16BE(val.flags & 0xFFFF);
  buff.copy(val.type_bitmap);
  return WRITE_RESOURCE_DONE;
}

// ZONEMD (RFC 8976 section 2.1).
function writeZonemd(buff, val) {
  assertUndefined(val.serial, 'ZONEMD record requires "serial"');
  assertUndefined(val.scheme, 'ZONEMD record requires "scheme"');
  assertUndefined(val.hash_algorithm, 'ZONEMD record requires "hash_algorithm"');
  assertUndefined(val.digest, 'ZONEMD record requires "digest"');
  buff.writeUInt32BE(val.serial >>> 0);
  buff.writeUInt8(val.scheme);
  buff.writeUInt8(val.hash_algorithm);
  buff.copy(val.digest);
  return WRITE_RESOURCE_DONE;
}

// SVCB (RFC 9460 section 2.2) and HTTPS share this layout. The target name is
// not compressed; SvcParams are kept as a list of {key, value-bytes}.
function writeSvcb(buff, val) {
  assertUndefined(val.priority, 'SVCB/HTTPS record requires "priority"');
  assertUndefined(val.target, 'SVCB/HTTPS record requires "target"');
  buff.writeUInt16BE(val.priority & 0xFFFF);
  namePackUncompressed(val.target, buff);
  var params = val.params || [];
  params.forEach(function(p) {
    buff.writeUInt16BE(p.key & 0xFFFF);
    buff.writeUInt16BE(p.value.length & 0xFFFF);
    buff.copy(p.value);
  });
  return WRITE_RESOURCE_DONE;
}

function makeEdns(packet) {
  packet.edns = {
    name: '',
    type: consts.NAME_TO_QTYPE.OPT,
    class: packet.payload,
    options: [],
    ttl: 0
  };
  packet.edns_options = packet.edns.options; // TODO: 'edns_options' is DEPRECATED!
  packet.additional.push(packet.edns);
  return WRITE_HEADER;
}

function writeOpt(buff, val) {
  var opt;
  for (var i=0, len=val.options.length; i<len; i++) {
    opt = val.options[i];
    buff.writeUInt16BE(opt.code);
    buff.writeUInt16BE(opt.data.length);
    buff.copy(opt.data);
  }
  return WRITE_RESOURCE_DONE;
}

Packet.write = function(buff, packet) {
  var state = WRITE_HEADER,
      val,
      section,
      count,
      rdata,
      last_resource,
      label_index = {};

  buff = new BufferCursor(buff);

  // the existence of 'edns' in a packet indicates that a proper OPT record exists
  // in 'additional' and that all of the other fields in packet (that are parsed by
  // 'parseOpt') are properly set. If it does not exist, we assume that the user
  // is requesting that we create one for them.
  if (typeof packet.edns_version !== 'undefined' && typeof packet.edns === "undefined")
    state = makeEdns(packet);

  // TODO: this is unnecessarily inefficient. rewrite this using a
  //       function table instead. (same for Packet.parse too).
  while (true) {
    try {
      switch (state) {
        case WRITE_HEADER:
          state = writeHeader(buff, packet);
          break;
        case WRITE_TRUNCATE:
          state = writeTruncate(buff, packet, section, last_resource);
          break;
        case WRITE_QUESTION:
          state = writeQuestion(buff, packet.question[0], label_index);
          section = 'answer';
          count = 0;
          break;
        case WRITE_RESOURCE_RECORD:
          last_resource = buff.tell();
          if (packet[section].length == count) {
            switch (section) {
              case 'answer':
                section = 'authority';
                state = WRITE_RESOURCE_RECORD;
                break;
              case 'authority':
                section = 'additional';
                state = WRITE_RESOURCE_RECORD;
                break;
              case 'additional':
                state = WRITE_END;
                break;
            }
            count = 0;
          } else {
            state = WRITE_RESOURCE_WRITE;
          }
          break;
        case WRITE_RESOURCE_WRITE:
          rdata = {};
          val = packet[section][count];
          state = writeResource(buff, val, label_index, rdata);
          break;
        case WRITE_RESOURCE_DONE:
          count += 1;
          state = writeResourceDone(buff, rdata);
          break;
        case WRITE_A:
        case WRITE_AAAA:
          state = writeIp(buff, val);
          break;
        case WRITE_NS:
        case WRITE_CNAME:
        case WRITE_PTR:
          state = writeCname(buff, val, label_index);
          break;
        case WRITE_DNAME:
          state = writeDname(buff, val);
          break;
        case WRITE_SPF:
        case WRITE_TXT:
          state = writeTxt(buff, val);
          break;
        case WRITE_CAA:
          state = writeCaa(buff, val);
          break;
        case WRITE_MX:
          state = writeMx(buff, val, label_index);
          break;
        case WRITE_SRV:
          state = writeSrv(buff, val, label_index);
          break;
        case WRITE_SOA:
          state = writeSoa(buff, val, label_index);
          break;
        case WRITE_OPT:
          state = writeOpt(buff, val);
          break;
        case WRITE_NAPTR:
          state = writeNaptr(buff, val, label_index);
          break;
        case WRITE_TLSA:
        case WRITE_SMIMEA:
          state = writeTlsa(buff, val);
          break;
        case WRITE_DS:
        case WRITE_CDS:
          state = writeDs(buff, val);
          break;
        case WRITE_DNSKEY:
          state = writeDnskey(buff, val);
          break;
        case WRITE_RRSIG:
          state = writeRrsig(buff, val);
          break;
        case WRITE_NSEC:
          state = writeNsec(buff, val);
          break;
        case WRITE_NSEC3:
          state = writeNsec3(buff, val);
          break;
        case WRITE_NSEC3PARAM:
          state = writeNsec3param(buff, val);
          break;
        case WRITE_SSHFP:
          state = writeSshfp(buff, val);
          break;
        case WRITE_CERT:
          state = writeCert(buff, val);
          break;
        case WRITE_DHCID:
          state = writeDhcid(buff, val);
          break;
        case WRITE_OPENPGPKEY:
          state = writeOpenpgpkey(buff, val);
          break;
        case WRITE_IPSECKEY:
          state = writeIpseckey(buff, val);
          break;
        case WRITE_URI:
          state = writeUri(buff, val);
          break;
        case WRITE_LOC:
          state = writeLoc(buff, val);
          break;
        case WRITE_CSYNC:
          state = writeCsync(buff, val);
          break;
        case WRITE_ZONEMD:
          state = writeZonemd(buff, val);
          break;
        case WRITE_SVCB:
        case WRITE_HTTPS:
          state = writeSvcb(buff, val);
          break;
        case WRITE_END:
          return buff.tell();
        default:
          if (typeof val.data !== 'object')
            throw new Error('Packet.write Unknown State: ' + state);
          // write unhandled RR type
          buff.copy(val.data);
          state = WRITE_RESOURCE_DONE;
      }
    } catch (e) {
      if (e instanceof BufferCursorOverflow) {
        state = WRITE_TRUNCATE;
      } else {
        throw e;
      }
    }
  }
};

function parseHeader(msg, packet) {
  packet.header.id = msg.readUInt16BE();
  var val = msg.readUInt16BE();
  packet.header.qr = (val & 0x8000) >> 15;
  packet.header.opcode = (val & 0x7800) >> 11;
  packet.header.aa = (val & 0x400) >> 10;
  packet.header.tc = (val & 0x200) >> 9;
  packet.header.rd = (val & 0x100) >> 8;
  packet.header.ra = (val & 0x80) >> 7;
  packet.header.res1 = (val & 0x40) >> 6;
  packet.header.res2 = (val & 0x20) >> 5;
  packet.header.res3 = (val & 0x10) >> 4;
  packet.header.rcode = (val & 0xF);
  packet.question = new Array(msg.readUInt16BE());
  packet.answer = new Array(msg.readUInt16BE());
  packet.authority = new Array(msg.readUInt16BE());
  packet.additional = new Array(msg.readUInt16BE());
  return PARSE_QUESTION;
}

function parseQuestion(msg, packet) {
  var val = {};
  val.name = nameUnpack(msg);
  val.type = msg.readUInt16BE();
  val.class = msg.readUInt16BE();
  packet.question[0] = val;
  assert(packet.question.length === 1);
  // TODO handle qdcount > 1 in practice no one sends this
  return PARSE_RESOURCE_RECORD;
}

function parseRR(msg, val, rdata) {
  val.name = nameUnpack(msg);
  val.type = msg.readUInt16BE();
  val.class = msg.readUInt16BE();
  val.ttl = msg.readUInt32BE();
  rdata.len = msg.readUInt16BE();
  return val.type;
}

function parseA(val, msg) {
  var address = '' +
    msg.readUInt8() +
    '.' + msg.readUInt8() +
    '.' + msg.readUInt8() +
    '.' + msg.readUInt8();
  val.address = address;
  return PARSE_RESOURCE_DONE;
}

function parseAAAA(val, msg) {
  var address = '';
  var compressed = false;

  for (var i = 0; i < 8; i++) {
    if (i > 0) address += ':';
    // TODO zero compression
    address += msg.readUInt16BE().toString(16);
  }
  val.address = address;
  return PARSE_RESOURCE_DONE;
}

function parseCname(val, msg) {
  val.data = nameUnpack(msg);
  return PARSE_RESOURCE_DONE;
}

function parseTxt(val, msg, rdata) {
  val.data = [];
  var end = msg.tell() + rdata.len;
  while (msg.tell() != end) {
    var len = msg.readUInt8();
    val.data.push(msg.toString('utf8', len));
  }
  return PARSE_RESOURCE_DONE;
}

function parseCaa(val, msg, rdata) {
  // RDATA layout (RFC 8659 section 4.1): flags (1) + tag length (1) + tag + value
  val.flags = msg.readUInt8();
  var len = msg.readUInt8();
  // Bytes left in this record after the flags and tag-length octets.
  var avail = Math.max(rdata.len - 2, 0);
  // Clamp a bogus tag length so we can't read past the record and compute a
  // negative value length, which would seek the cursor backwards and desync
  // parsing of any records that follow.
  if (len > avail)
    len = avail;
  val.tag = msg.toString('utf8', len);
  val.data = msg.toString('utf8', avail - len);
  return PARSE_RESOURCE_DONE;
}

function parseMx(val, msg, rdata) {
  val.priority = msg.readUInt16BE();
  val.exchange = nameUnpack(msg);
  return PARSE_RESOURCE_DONE;
}

// https://tools.ietf.org/html/rfc2782
function parseSrv(val, msg) {
  val.priority = msg.readUInt16BE();
  val.weight = msg.readUInt16BE();
  val.port = msg.readUInt16BE();
  val.target = nameUnpack(msg);
  return PARSE_RESOURCE_DONE;
}

function parseSoa(val, msg) {
  val.primary = nameUnpack(msg);
  val.admin = nameUnpack(msg);
  val.serial = msg.readUInt32BE();
  val.refresh = msg.readInt32BE();
  val.retry = msg.readInt32BE();
  val.expiration = msg.readInt32BE();
  val.minimum = msg.readInt32BE();
  return PARSE_RESOURCE_DONE;
}

// http://tools.ietf.org/html/rfc3403#section-4.1
function parseNaptr(val, msg) {
  val.order = msg.readUInt16BE();
  val.preference = msg.readUInt16BE();
  var len = msg.readUInt8();
  val.flags = msg.toString('ascii', len);
  len = msg.readUInt8();
  val.service = msg.toString('ascii', len);
  len = msg.readUInt8();
  val.regexp = msg.toString('ascii', len);
  val.replacement = nameUnpack(msg);
  return PARSE_RESOURCE_DONE;
}

function parseTlsa(val, msg, rdata) {
  val.usage = msg.readUInt8();
  val.selector = msg.readUInt8();
  val.matchingtype = msg.readUInt8();
  val.buff = msg.slice(rdata.len - 3).buffer; // 3 because of the 3 UInt8s above.
  return PARSE_RESOURCE_DONE;
}

function parseDs(val, msg, rdata) {
  var end = msg.tell() + rdata.len;
  val.key_tag = msg.readUInt16BE();
  val.algorithm = msg.readUInt8();
  val.digest_type = msg.readUInt8();
  val.digest = msg.slice(end - msg.tell()).buffer;
  return PARSE_RESOURCE_DONE;
}

function parseDnskey(val, msg, rdata) {
  var end = msg.tell() + rdata.len;
  val.flags = msg.readUInt16BE();
  val.protocol = msg.readUInt8();
  val.algorithm = msg.readUInt8();
  val.public_key = msg.slice(end - msg.tell()).buffer;
  return PARSE_RESOURCE_DONE;
}

function parseRrsig(val, msg, rdata) {
  var end = msg.tell() + rdata.len;
  val.type_covered = msg.readUInt16BE();
  val.algorithm = msg.readUInt8();
  val.labels = msg.readUInt8();
  val.original_ttl = msg.readUInt32BE();
  val.expiration = msg.readUInt32BE();
  val.inception = msg.readUInt32BE();
  val.key_tag = msg.readUInt16BE();
  val.signer = nameUnpack(msg);
  val.signature = msg.slice(end - msg.tell()).buffer;
  return PARSE_RESOURCE_DONE;
}

function parseNsec(val, msg, rdata) {
  var end = msg.tell() + rdata.len;
  val.next_domain = nameUnpack(msg);
  val.type_bitmap = msg.slice(end - msg.tell()).buffer;
  return PARSE_RESOURCE_DONE;
}

function parseNsec3(val, msg, rdata) {
  var end = msg.tell() + rdata.len;
  val.hash_algorithm = msg.readUInt8();
  val.flags = msg.readUInt8();
  val.iterations = msg.readUInt16BE();
  val.salt = msg.slice(msg.readUInt8()).buffer;
  val.next_hashed_owner = msg.slice(msg.readUInt8()).buffer;
  val.type_bitmap = msg.slice(end - msg.tell()).buffer;
  return PARSE_RESOURCE_DONE;
}

function parseNsec3param(val, msg, rdata) {
  val.hash_algorithm = msg.readUInt8();
  val.flags = msg.readUInt8();
  val.iterations = msg.readUInt16BE();
  val.salt = msg.slice(msg.readUInt8()).buffer;
  return PARSE_RESOURCE_DONE;
}

function parseSshfp(val, msg, rdata) {
  var end = msg.tell() + rdata.len;
  val.algorithm = msg.readUInt8();
  val.fptype = msg.readUInt8();
  val.fingerprint = msg.slice(end - msg.tell()).buffer;
  return PARSE_RESOURCE_DONE;
}

function parseCert(val, msg, rdata) {
  var end = msg.tell() + rdata.len;
  val.cert_type = msg.readUInt16BE();
  val.key_tag = msg.readUInt16BE();
  val.algorithm = msg.readUInt8();
  val.certificate = msg.slice(end - msg.tell()).buffer;
  return PARSE_RESOURCE_DONE;
}

function parseDhcid(val, msg, rdata) {
  val.data = msg.slice(rdata.len).buffer;
  return PARSE_RESOURCE_DONE;
}

function parseOpenpgpkey(val, msg, rdata) {
  val.public_key = msg.slice(rdata.len).buffer;
  return PARSE_RESOURCE_DONE;
}

function parseIpseckey(val, msg, rdata) {
  var end = msg.tell() + rdata.len;
  val.precedence = msg.readUInt8();
  val.gateway_type = msg.readUInt8();
  val.algorithm = msg.readUInt8();
  switch (val.gateway_type) {
    case 0:
      val.gateway = '';
      break;
    case 1:
      val.gateway = ipv4FromBytes(msg.slice(4).buffer);
      break;
    case 2:
      val.gateway = ipv6FromBytes(msg.slice(16).buffer);
      break;
    case 3:
      val.gateway = nameUnpack(msg);
      break;
    default:
      throw new Error('IPSECKEY unknown gateway_type: ' + val.gateway_type);
  }
  val.public_key = msg.slice(end - msg.tell()).buffer;
  return PARSE_RESOURCE_DONE;
}

function parseUri(val, msg, rdata) {
  var end = msg.tell() + rdata.len;
  val.priority = msg.readUInt16BE();
  val.weight = msg.readUInt16BE();
  val.target = msg.toString('utf8', end - msg.tell());
  return PARSE_RESOURCE_DONE;
}

function parseLoc(val, msg, rdata) {
  val.version = msg.readUInt8();
  val.size = msg.readUInt8();
  val.horizontal_precision = msg.readUInt8();
  val.vertical_precision = msg.readUInt8();
  val.latitude = msg.readUInt32BE();
  val.longitude = msg.readUInt32BE();
  val.altitude = msg.readUInt32BE();
  return PARSE_RESOURCE_DONE;
}

function parseCsync(val, msg, rdata) {
  var end = msg.tell() + rdata.len;
  val.serial = msg.readUInt32BE();
  val.flags = msg.readUInt16BE();
  val.type_bitmap = msg.slice(end - msg.tell()).buffer;
  return PARSE_RESOURCE_DONE;
}

function parseZonemd(val, msg, rdata) {
  var end = msg.tell() + rdata.len;
  val.serial = msg.readUInt32BE();
  val.scheme = msg.readUInt8();
  val.hash_algorithm = msg.readUInt8();
  val.digest = msg.slice(end - msg.tell()).buffer;
  return PARSE_RESOURCE_DONE;
}

function parseSvcb(val, msg, rdata) {
  var end = msg.tell() + rdata.len;
  val.priority = msg.readUInt16BE();
  val.target = nameUnpack(msg);
  val.params = [];
  while (msg.tell() < end) {
    var key = msg.readUInt16BE();
    var len = msg.readUInt16BE();
    val.params.push({ key: key, value: msg.slice(len).buffer });
  }
  return PARSE_RESOURCE_DONE;
}

// https://tools.ietf.org/html/rfc6891#section-6.1.2
// https://tools.ietf.org/html/rfc2671#section-4.4
//       - [payload size selection](https://tools.ietf.org/html/rfc6891#section-6.2.5)
function parseOpt(val, msg, rdata, packet) {
  // assert first entry in additional
  rdata.buf = msg.slice(rdata.len);

  val.rcode = ((val.ttl & 0xFF000000) >> 20) + packet.header.rcode;
  val.version = (val.ttl >> 16) & 0xFF;
  val.do = (val.ttl >> 15) & 1;
  val.z = val.ttl & 0x7F;
  val.options = [];

  packet.edns = val;
  packet.edns_version = val.version; // TODO: return BADVERS for unsupported version! (Section 6.1.3)

  // !! BEGIN DEPRECATION NOTICE !!
  // THESE FIELDS MAY BE REMOVED IN THE FUTURE!
  packet.edns_options = val.options;
  packet.payload = val.class;
  // !! END DEPRECATION NOTICE !!

  while (!rdata.buf.eof()) {
    val.options.push({
      code: rdata.buf.readUInt16BE(),
      data: rdata.buf.slice(rdata.buf.readUInt16BE()).buffer
    });
  }
  return PARSE_RESOURCE_DONE;
}

var
  PARSE_HEADER          = 100000,
  PARSE_QUESTION        = 100001,
  PARSE_RESOURCE_RECORD = 100002,
  PARSE_RR_UNPACK       = 100003,
  PARSE_RESOURCE_DONE   = 100004,
  PARSE_END             = 100005,
  PARSE_A     = consts.NAME_TO_QTYPE.A,
  PARSE_NS    = consts.NAME_TO_QTYPE.NS,
  PARSE_CNAME = consts.NAME_TO_QTYPE.CNAME,
  PARSE_SOA   = consts.NAME_TO_QTYPE.SOA,
  PARSE_PTR   = consts.NAME_TO_QTYPE.PTR,
  PARSE_MX    = consts.NAME_TO_QTYPE.MX,
  PARSE_TXT   = consts.NAME_TO_QTYPE.TXT,
  PARSE_CAA   = consts.NAME_TO_QTYPE.CAA,
  PARSE_AAAA  = consts.NAME_TO_QTYPE.AAAA,
  PARSE_SRV   = consts.NAME_TO_QTYPE.SRV,
  PARSE_NAPTR = consts.NAME_TO_QTYPE.NAPTR,
  PARSE_OPT   = consts.NAME_TO_QTYPE.OPT,
  PARSE_SPF   = consts.NAME_TO_QTYPE.SPF,
  PARSE_TLSA  = consts.NAME_TO_QTYPE.TLSA,
  PARSE_DNAME = consts.NAME_TO_QTYPE.DNAME,
  PARSE_DS         = consts.NAME_TO_QTYPE.DS,
  PARSE_CDS        = consts.NAME_TO_QTYPE.CDS,
  PARSE_DNSKEY     = consts.NAME_TO_QTYPE.DNSKEY,
  PARSE_RRSIG      = consts.NAME_TO_QTYPE.RRSIG,
  PARSE_NSEC       = consts.NAME_TO_QTYPE.NSEC,
  PARSE_NSEC3      = consts.NAME_TO_QTYPE.NSEC3,
  PARSE_NSEC3PARAM = consts.NAME_TO_QTYPE.NSEC3PARAM,
  PARSE_SSHFP      = consts.NAME_TO_QTYPE.SSHFP,
  PARSE_SMIMEA     = consts.NAME_TO_QTYPE.SMIMEA,
  PARSE_CERT       = consts.NAME_TO_QTYPE.CERT,
  PARSE_DHCID      = consts.NAME_TO_QTYPE.DHCID,
  PARSE_OPENPGPKEY = consts.NAME_TO_QTYPE.OPENPGPKEY,
  PARSE_IPSECKEY   = consts.NAME_TO_QTYPE.IPSECKEY,
  PARSE_URI        = consts.NAME_TO_QTYPE.URI,
  PARSE_LOC        = consts.NAME_TO_QTYPE.LOC,
  PARSE_CSYNC      = consts.NAME_TO_QTYPE.CSYNC,
  PARSE_ZONEMD     = consts.NAME_TO_QTYPE.ZONEMD,
  PARSE_SVCB       = consts.NAME_TO_QTYPE.SVCB,
  PARSE_HTTPS      = consts.NAME_TO_QTYPE.HTTPS;


Packet.parse = function(msg) {
  var state,
      pos,
      val,
      rdata,
      section,
      count;

  var packet = new Packet();

  pos = 0;
  state = PARSE_HEADER;

  msg = new BufferCursor(msg);

  while (true) {
    switch (state) {
      case PARSE_HEADER:
        state = parseHeader(msg, packet);
        break;
      case PARSE_QUESTION:
        state = parseQuestion(msg, packet);
        section = 'answer';
        count = 0;
        break;
      case PARSE_RESOURCE_RECORD:
        // console.log('PARSE_RESOURCE_RECORD: count = %d, %s.len = %d', count, section, packet[section].length);
        if (count === packet[section].length) {
          switch (section) {
            case 'answer':
              section = 'authority';
              count = 0;
              break;
            case 'authority':
              section = 'additional';
              count = 0;
              break;
            case 'additional':
              state = PARSE_END;
              break;
          }
        } else {
          state = PARSE_RR_UNPACK;
        }
        break;
      case PARSE_RR_UNPACK:
        val = {};
        rdata = {};
        state = parseRR(msg, val, rdata);
        break;
      case PARSE_RESOURCE_DONE:
        packet[section][count++] = val;
        state = PARSE_RESOURCE_RECORD;
        break;
      case PARSE_A:
        state = parseA(val, msg);
        break;
      case PARSE_AAAA:
        state = parseAAAA(val, msg);
        break;
      case PARSE_NS:
      case PARSE_CNAME:
      case PARSE_PTR:
      case PARSE_DNAME:
        state = parseCname(val, msg);
        break;
      case PARSE_SPF:
      case PARSE_TXT:
        state = parseTxt(val, msg, rdata);
        break;
      case PARSE_CAA:
        state = parseCaa(val, msg, rdata);
        break;
      case PARSE_MX:
        state = parseMx(val, msg);
        break;
      case PARSE_SRV:
        state = parseSrv(val, msg);
        break;
      case PARSE_SOA:
        state = parseSoa(val, msg);
        break;
      case PARSE_OPT:
        state = parseOpt(val, msg, rdata, packet);
        break;
      case PARSE_NAPTR:
        state = parseNaptr(val, msg);
        break;
      case PARSE_TLSA:
      case PARSE_SMIMEA:
        state = parseTlsa(val, msg, rdata);
        break;
      case PARSE_DS:
      case PARSE_CDS:
        state = parseDs(val, msg, rdata);
        break;
      case PARSE_DNSKEY:
        state = parseDnskey(val, msg, rdata);
        break;
      case PARSE_RRSIG:
        state = parseRrsig(val, msg, rdata);
        break;
      case PARSE_NSEC:
        state = parseNsec(val, msg, rdata);
        break;
      case PARSE_NSEC3:
        state = parseNsec3(val, msg, rdata);
        break;
      case PARSE_NSEC3PARAM:
        state = parseNsec3param(val, msg, rdata);
        break;
      case PARSE_SSHFP:
        state = parseSshfp(val, msg, rdata);
        break;
      case PARSE_CERT:
        state = parseCert(val, msg, rdata);
        break;
      case PARSE_DHCID:
        state = parseDhcid(val, msg, rdata);
        break;
      case PARSE_OPENPGPKEY:
        state = parseOpenpgpkey(val, msg, rdata);
        break;
      case PARSE_IPSECKEY:
        state = parseIpseckey(val, msg, rdata);
        break;
      case PARSE_URI:
        state = parseUri(val, msg, rdata);
        break;
      case PARSE_LOC:
        state = parseLoc(val, msg, rdata);
        break;
      case PARSE_CSYNC:
        state = parseCsync(val, msg, rdata);
        break;
      case PARSE_ZONEMD:
        state = parseZonemd(val, msg, rdata);
        break;
      case PARSE_SVCB:
      case PARSE_HTTPS:
        state = parseSvcb(val, msg, rdata);
        break;
      case PARSE_END:
        return packet;
      default:
        //console.log(state, val);
        val.data = msg.slice(rdata.len);
        state = PARSE_RESOURCE_DONE;
        break;
    }
  }
};
