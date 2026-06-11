{
  header: {
    id: 9,
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
      name: '_smimecert.example.com',
      type: 53,
      class: 1
    }
  ],
  answer: [
    {
      name: '_smimecert.example.com',
      type: 53,
      class: 1,
      ttl: 3600,
      usage: 3,
      selector: 1,
      matchingtype: 1,
      buff: Buffer.from([0x92, 0x00, 0x3b, 0xa3, 0x34, 0x9b, 0x0a, 0xff, 0x00])
    }
  ],
  authority: [],
  additional: [],
  edns_options: [],
  payload: undefined
}
