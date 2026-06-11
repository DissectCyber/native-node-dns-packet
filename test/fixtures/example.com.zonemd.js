{
  header: {
    id: 20,
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
      type: 63,
      class: 1
    }
  ],
  answer: [
    {
      name: 'example.com',
      type: 63,
      class: 1,
      ttl: 3600,
      serial: 2018031900,
      scheme: 1,
      hash_algorithm: 1,
      digest: Buffer.from([0xfe, 0xbe, 0x3d, 0x4c, 0xe2, 0xec, 0x2f, 0xfa, 0x4b, 0xa9, 0x9d, 0x46, 0xcd, 0x69, 0xd6, 0xd2])
    }
  ],
  authority: [],
  additional: [],
  edns_options: [],
  payload: undefined
}
