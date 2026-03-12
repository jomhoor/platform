const {ethers} = require('ethers');
const p = new ethers.JsonRpcProvider('http://127.0.0.1:8545');
async function check() {
  const addrs = [
    ['IDCardVoting (prev)', '0x687bB6c57915aa2529EfC7D2a26668855e022fAE'],
    ['BioPassportVoting', '0xC0BF43A4Ca27e0976195E6661b099742f10507e5'],
    ['ProposalsState', '0x0bF7dE8d71820840063D4B8653Fd3F0618986faF'],
  ];
  for (const [name, addr] of addrs) {
    const code = await p.getCode(addr);
    console.log(name + ' ' + addr + ': ' + (code.length > 2 ? 'HAS CODE' : 'NO CODE'));
  }

  // Check the migration cache
  const fs = require('fs');
  try {
    const cache = JSON.parse(fs.readFileSync('cache/.migrate.storage.json', 'utf8'));
    // Look for IDCard in any key
    for (const [k,v] of Object.entries(cache.storage || cache)) {
      if (typeof v === 'string' && (k.toLowerCase().includes('idcard') || k.toLowerCase().includes('id_card') || k.toLowerCase().includes('noir')))
        console.log('Cache:', k, '=', v);
    }
  } catch(e) { console.log('Cache error:', e.message); }
}
check();
