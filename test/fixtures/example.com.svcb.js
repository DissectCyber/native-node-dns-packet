{
  header: {
    id: 21,
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
      name: '_dns.example.com',
      type: 64,
      class: 1
    }
  ],
  answer: [
    {
      name: '_dns.example.com',
      type: 64,
      class: 1,
      ttl: 3600,
      priority: 1,
      target: 'svc.example.net',
      params: [
        {
          key: 1,
          value: Buffer.from([0x02, 0x68, 0x32])
        },
        {
          key: 3,
          value: Buffer.from([0x01, 0xbb])
        }
      ]
    }
  ],
  authority: [],
  additional: [],
  edns_options: [],
  payload: undefined
}
