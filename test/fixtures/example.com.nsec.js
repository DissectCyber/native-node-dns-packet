{
  header: {
    id: 5,
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
      type: 47,
      class: 1
    }
  ],
  answer: [
    {
      name: 'example.com',
      type: 47,
      class: 1,
      ttl: 3600,
      next_domain: 'a.example.com',
      type_bitmap: Buffer.from([0x00, 0x06, 0x40, 0x01, 0x00, 0x00, 0x00, 0x03])
    }
  ],
  authority: [],
  additional: [],
  edns_options: [],
  payload: undefined
}
