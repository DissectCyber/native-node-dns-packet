{
  header: {
    id: 19,
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
      type: 62,
      class: 1
    }
  ],
  answer: [
    {
      name: 'example.com',
      type: 62,
      class: 1,
      ttl: 3600,
      serial: 66,
      flags: 3,
      type_bitmap: Buffer.from([0x00, 0x04, 0x60, 0x00, 0x00, 0x08])
    }
  ],
  authority: [],
  additional: [],
  edns_options: [],
  payload: undefined
}
