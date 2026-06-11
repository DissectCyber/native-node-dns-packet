{
  header: {
    id: 2,
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
      type: 59,
      class: 1
    }
  ],
  answer: [
    {
      name: 'example.com',
      type: 59,
      class: 1,
      ttl: 3600,
      key_tag: 60485,
      algorithm: 5,
      digest_type: 1,
      digest: Buffer.from([0x2b, 0xb1, 0x83, 0xaf, 0x5f, 0x22, 0x58, 0x81, 0x79, 0xa5, 0x3b, 0x0a, 0x98, 0x63, 0x1f, 0xad, 0x1a, 0x29, 0x21, 0x18])
    }
  ],
  authority: [],
  additional: [],
  edns_options: [],
  payload: undefined
}
