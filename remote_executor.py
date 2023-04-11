import paramiko
import socket
import time
from paramiko.ssh_exception import AuthenticationException, SSHException
from paramiko import ChannelException


def remote_execute_command(hostname, port, username, password, command, timeout=10):
    result = {
        'stdout': '',
        'stderr': '',
        'err':'',
        'status': 'success',
        'exitCode': None
    }
    try:
        # 创建 SSH 客户端
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # 连接远程主机
        client.connect(hostname, port, username, password, timeout=timeout)

        # 执行远程命令
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')
        if output:
            result['stdout'] = output
        if error:
            result['error'] = error
        result['exitCode'] = stdout.channel.recv_exit_status()


    except AuthenticationException:
        print("Error: Authentication failed.")
        result['status'] = 'failed'
        result['err'] = 'Error: Authentication failed.'
    except SSHException as e:
        print(f"Error: SSH exception occurred - {e}")
    except socket.timeout:
        print(f"Error: Socket timeout occurred while connecting to {hostname}:{port}")
    except ChannelException:
        print("Error: Channel exception occurred.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        # 关闭连接
        client.close()

    return result
