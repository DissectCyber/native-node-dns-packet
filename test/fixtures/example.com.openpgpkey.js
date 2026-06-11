{
  header: {
    id: 12,
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
      type: 61,
      class: 1
    }
  ],
  answer: [
    {
      name: 'example.com',
      type: 61,
      class: 1,
      ttl: 3600,
      public_key: Buffer.from([0x99, 0x01, 0x0d, 0x04, 0x55, 0x6f, 0x8a])
    }
  ],
  authority: [],
  additional: [],
  edns_options: [],
  payload: undefined
}
