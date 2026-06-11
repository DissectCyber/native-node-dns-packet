{
  header: {
    id: 3,
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
      type: 48,
      class: 1
    }
  ],
  answer: [
    {
      name: 'example.com',
      type: 48,
      class: 1,
      ttl: 3600,
      flags: 256,
      protocol: 3,
      algorithm: 5,
      public_key: Buffer.from([0x03, 0x01, 0x00, 0x01, 0xab, 0xcd, 0xef])
    }
  ],
  authority: [],
  additional: [],
  edns_options: [],
  payload: undefined
}
