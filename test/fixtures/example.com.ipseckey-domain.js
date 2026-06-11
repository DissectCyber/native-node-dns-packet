{
  header: {
    id: 15,
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
      gateway_type: 3,
      algorithm: 2,
      gateway: 'gateway.example.com',
      public_key: Buffer.from([0x09, 0x0a, 0x0b, 0x0c])
    }
  ],
  authority: [],
  additional: [],
  edns_options: [],
  payload: undefined
}
