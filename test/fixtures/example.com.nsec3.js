{
  header: {
    id: 6,
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
      type: 50,
      class: 1
    }
  ],
  answer: [
    {
      name: 'example.com',
      type: 50,
      class: 1,
      ttl: 3600,
      hash_algorithm: 1,
      flags: 0,
      iterations: 10,
      salt: Buffer.from([0xaa, 0xbb, 0xcc]),
      next_hashed_owner: Buffer.from([0x12, 0x34, 0x56, 0x78, 0x9a]),
      type_bitmap: Buffer.from([0x00, 0x06, 0x40, 0x01, 0x00, 0x00, 0x00, 0x03])
    }
  ],
  authority: [],
  additional: [],
  edns_options: [],
  payload: undefined
}
