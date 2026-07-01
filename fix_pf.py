from soar.clients.pfsense_client import PfSenseClient
c = PfSenseClient()
c.connect()
rules = 'table <blocklist> persist\npass in on em2 all\npass out on em2 all\nblock drop quick from <blocklist> to any\nblock drop quick from any to <blocklist>\n'
cmd = f'printf "{rules}" | pfctl -f -'
out, err = c._exec(cmd)
print('Regles:', out, err)
out2, err2 = c._exec('pfctl -sr')
print('Actives:', out2)
c.disconnect()
