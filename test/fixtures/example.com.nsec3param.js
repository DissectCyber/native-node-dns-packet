{
  header: {
    id: 7,
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
      type: 51,
      class: 1
    }
  ],
  answer: [
    {
      name: 'example.com',
      type: 51,
      class: 1,
      ttl: 3600,
      hash_algorithm: 1,
      flags: 0,
      iterations: 10,
      salt: Buffer.from([0xaa, 0xbb, 0xcc])
    }
  ],
  authority: [],
  additional: [],
  edns_options: [],
  payload: undefined
}
