{
  header: {
    id: 4,
    qr: 1,
    opcode: 0,
    aa: 0,
    tc: 0,
    rd: 1,
    ra: 1,
    res1: 0,
    res2: 0,
    res3: 0,
    rcode: 0
  },
  question: [
    {
      name: 'example.com',
      type: 46,
      class: 1
    }
  ],
  answer: [
    {
      name: 'example.com',
      type: 46,
      class: 1,
      ttl: 3600,
      type_covered: 1,
      algorithm: 5,
      labels: 2,
      original_ttl: 3600,
      expiration: 1700000000,
      inception: 1690000000,
      key_tag: 60485,
      signer: 'example.com',
      signature: Buffer.from([0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04])
    }
  ],
  authority: [],
  additional: [],
  edns_options: [],
  payload: undefined
}
