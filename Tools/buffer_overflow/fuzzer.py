import socket, time, sys
import click


@click.argument('ip')
@click.argument('port')
@click.option('--payload', '-p', default='')
@click.option('--max', '-m', default=30)
def main(ip, port, payload, max, timeout):
    buffer = []
    counter = 100
    while len(buffer) < max:
        buffer.append("A" * counter)
        counter += 100

    for string in buffer:
        try:
            s = socket.create_connection((ip, port))
            s.recv(1024)
            print("Fuzzing with %s bytes" % len(buffer))
            string = payload + ' ' + string + "\r\n"
            s.send(string.encode())
            s.recv(1024)
            s.close()
        except OSError as e:
            print("Could not connect to " + ip + ":" + str(port))
            print(e)
            sys.exit(0)
        time.sleep(1)

