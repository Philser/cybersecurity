import socket, time, sys
import click

timeout = 5

@click.command()
@click.argument('ip')
@click.argument('port')
@click.option('--payload', '-p', default = '')
@click.option('--max', '-m', default = 30)
def main(ip, port, payload, max):
    buffer = []
    counter = 100
    while len(buffer) < max:
        buffer.append("A" * counter)
        counter += 100

    for string in buffer:
        try:
            # s = socket.socket()
            # s.settimeout(timeout)
            s = socket.create_connection((ip, port))
            s.recv(1024)
            print("Fuzzing with %s bytes" % len(string))
            to_send = payload + ' ' + string + "\r\n"
            s.send(to_send.encode())
            s.recv(1024)
            s.close()
        except OSError as err:
            print(err)
            print("Could not connect to " + ip + ":" + str(port))
            sys.exit(0)
        time.sleep(1)

if __name__ == "__main__":
    main()