{
  header: {
    id: 10,
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
      type: 37,
      class: 1
    }
  ],
  answer: [
    {
      name: 'example.com',
      type: 37,
      class: 1,
      ttl: 3600,
      cert_type: 1,
      key_tag: 60485,
      algorithm: 5,
      certificate: Buffer.from([0x30, 0x82, 0x01, 0x0a, 0x02, 0x82])
    }
  ],
  authority: [],
  additional: [],
  edns_options: [],
  payload: undefined
}
