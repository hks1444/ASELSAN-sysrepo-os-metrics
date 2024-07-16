from ncclient import manager
from lxml import etree
manager1 = None
# Replace with your Netopeer server details
host = ''
port = 830
username = ''
password = ''

def send_rpc_request(rpc_request):
    global manager1
    manager1 = manager.connect(
        host=host,
        port=port,
        username=username,
        password=password,
        hostkey_verify=False
    )
    response = manager1.dispatch(etree.fromstring(rpc_request))
    print(response)


if __name__ == "__main__":
    rpc_request1 = """
        <freeg xmlns="ASELSAN-Sysrepo-OS-Metrics"/>
        """
    rpc_request2 = """
        <uptime xmlns="ASELSAN-Sysrepo-OS-Metrics"/>
        """
        
    rpc_request3 = """
        <set-time xmlns="ASELSAN-Sysrepo-OS-Metrics">
            <newtime>12:34:56</newtime>
        </set-time>
        """
    rpc_request4 = """
        <sync-time xmlns="ASELSAN-Sysrepo-OS-Metrics"/>
        """
        
    rpc_request5 = """
        <get-ip xmlns="ASELSAN-Sysrepo-OS-Metrics"/>
        """
    send_rpc_request(rpc_request5)
    send_rpc_request(rpc_request2)
    send_rpc_request(rpc_request3)
    send_rpc_request(rpc_request4)


