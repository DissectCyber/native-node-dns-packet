{
  header: {
    id: 11,
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
      type: 49,
      class: 1
    }
  ],
  answer: [
    {
      name: 'example.com',
      type: 49,
      class: 1,
      ttl: 3600,
      data: Buffer.from([0x00, 0x02, 0x01, 0x63, 0x6f, 0xc4, 0x84, 0xfd, 0xa9, 0x4c])
    }
  ],
  authority: [],
  additional: [],
  edns_options: [],
  payload: undefined
}
