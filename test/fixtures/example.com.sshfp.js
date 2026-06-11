{
  header: {
    id: 8,
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
      type: 44,
      class: 1
    }
  ],
  answer: [
    {
      name: 'example.com',
      type: 44,
      class: 1,
      ttl: 3600,
      algorithm: 1,
      fptype: 1,
      fingerprint: Buffer.from([0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78])
    }
  ],
  authority: [],
  additional: [],
  edns_options: [],
  payload: undefined
}
