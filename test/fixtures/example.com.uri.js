{
  header: {
    id: 17,
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
      name: '_http._tcp.example.com',
      type: 256,
      class: 1
    }
  ],
  answer: [
    {
      name: '_http._tcp.example.com',
      type: 256,
      class: 1,
      ttl: 3600,
      priority: 10,
      weight: 1,
      target: 'https://www.example.com/'
    }
  ],
  authority: [],
  additional: [],
  edns_options: [],
  payload: undefined
}
