{
  header: {
    id: 5183,
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
  question: [ { name: 'sip2sip.info', type: 35, class: 1 } ],
  answer: [
    {
      name: 'sip2sip.info',
      type: 35,
      class: 1,
      ttl: 600,
      order: 10,
      preference: 0,
      flags: 'S',
      service: 'SIP+D2U',
      regexp: '',
      replacement: '_sip._udp.sip2sip.info'
    }
  ],
  authority: [],
  additional: [],
  edns_options: [],
  payload: undefined
}
