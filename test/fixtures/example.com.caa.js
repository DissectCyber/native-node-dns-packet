{
  header: {
    id: 51223,
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
  question: [ { name: 'example.com', type: 257, class: 1 } ],
  answer: [
    {
      name: 'example.com',
      type: 257,
      class: 1,
      ttl: 60,
      flags: 0,
      tag: 'issue',
      data: 'letsencrypt.org'
    }
  ],
  authority: [],
  additional: [],
  edns_options: [],
  payload: undefined
}
