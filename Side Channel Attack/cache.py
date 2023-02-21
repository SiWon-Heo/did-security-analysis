import numpy as np
import matplotlib.pyplot as plt

log_list = ['abt', 'ace', 'bba', 'bid', 'btcr', 'ccp', 'cy', 'dock', 'echo', 'elem', 'erc725', 'ethr', 'ethr2', 'factom',
            'gatc', 'github', 'hcr', 'io', 'ion', 'ipid', 'jolo', 'key', 'kilt', 'mpg', 'nacl',
            'neoid', 'ont', 'schema', 'sirius', 'sov', 'stack', 'trust', 'trustbloc', 'v1', 'web', 'work']

target_cache_time = []
server_work = [0 for i in range(len(log_list))]
for i in range(len(log_list)):
    sub_target_cache_time = []
    target_filename = log_list[i] + '.txt'
    target_file = open(target_filename, 'r')
    a = open('cy.txt', 'r').readline()
    print(a)
    while (a != ''):
        a = target_file.readline()
        if 'real' in a:
            cache_time = float(a.split('\t')[1].split('s')[0].split('m')[1])
            sub_target_cache_time.append(cache_time)
        if 'Not Found' in a:
            server_work[i] -= 1
        if 'Error' in a:
            server_work[i] -= 1

    target_cache_time.append(sub_target_cache_time)

for i in range(len(log_list)):
    if server_work[i] == 0:
        server_work[i] = len(target_cache_time[i])

for i in range(len(log_list)):
    if server_work[i] != 100:
        print('Blockchain {} does not work'.format(log_list[i]))
        server_work[i] = 0

print(server_work)

for i in range(len(log_list)):
    image_name = log_list[i]+'.jpg'
    if server_work[i] == 100:
        # x = np.linspace(0, 98, 98)
        y = target_cache_time[i][2:]
        plt.figure(i+1)
        plt.hist(y, bins=100, histtype='step')
        plt.title(image_name)
        plt.xlabel('sequence')
        plt.ylabel('time')
        # plt.show()
        plt.savefig(image_name)