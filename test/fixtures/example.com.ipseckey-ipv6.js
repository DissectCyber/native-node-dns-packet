{
  header: {
    id: 14,
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
      type: 45,
      class: 1
    }
  ],
  answer: [
    {
      name: 'example.com',
      type: 45,
      class: 1,
      ttl: 3600,
      precedence: 10,
      gateway_type: 2,
      algorithm: 2,
      gateway: '2001:db8:0:0:0:0:0:1',
      public_key: Buffer.from([0x05, 0x06, 0x07, 0x08])
    }
  ],
  authority: [],
  additional: [],
  edns_options: [],
  payload: undefined
}
