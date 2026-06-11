{
  header: {
    id: 22,
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
      type: 65,
      class: 1
    }
  ],
  answer: [
    {
      name: 'example.com',
      type: 65,
      class: 1,
      ttl: 3600,
      priority: 1,
      target: '',
      params: [
        {
          key: 1,
          value: Buffer.from([0x02, 0x68, 0x33])
        }
      ]
    }
  ],
  authority: [],
  additional: [],
  edns_options: [],
  payload: undefined
}
