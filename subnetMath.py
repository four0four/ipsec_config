
#http://wiki.python.org/moin/BitManipulation
def countBits(int_type):
    count = 0
    while(int_type):
        int_type &= int_type - 1
        count += 1
    return(count)

class Subnet:
    #10.20.30.40/24, for example
    def __init__(self, subnet, netmask = None):
        if netmask != None: #w.x.y.z and nm
            self.IP = subet.split('.') #should really rename it, plays two parts
            self.netmask = netmask.split('.')
            self.subnet = self.toSubnet() #only string
            self.broadcast = self.toBroadcast()
        else: #w.x.y.z/bits or about to throw an error
            self.subnet = subnet #only string
            self.IP = self.toIPaddress()
            self.netmask = self.splitCombined()[2]
            self.broadcast = self.toBroadcast()

    def toIPaddress(self):
        self.IP = self.subnet.partition('/')[0].split('.')
        return self.IP

    def toNetmask(self):
        self.netmask = self.splitCombined()[2]
        return self.netmask

    def toBroadcast(self):
        self.broadcast = ['0','0','0','0']
        netmask_octets = self.netmask
        ip_octets = self.IP
        for octet in range(4):
            self.broadcast[octet] = ((~int(netmask_octets[octet])) & 0xFF) | int(ip_octets[octet])
        return self.broadcast

    def splitCombined(self):
        netmask_bits = int(self.subnet.partition('/')[2])
        ip_string = str(self.subnet.partition('/')[0])
        ip_octets = ip_string.split('.')
        netmask_octets = ['0','0','0','0']
        netmask = ""
        trailing = netmask_bits % 8
        filled_octets = netmask_bits/8
        filled = 0
        for i in range(int(filled_octets)-1,-1,-1):
            tmp = 0
            for j in range(7,-1,-1):
                tmp |= (1<<j)
                filled += 1
            netmask_octets[i] = tmp
        if trailing != 0:
            tmp = 0
            partial_octet = (netmask_bits/8)
            for i in range(7,7-(netmask_bits - filled),-1):
                tmp |= (1<<i)
            netmask_octets[partial_octet] = tmp
        return(ip_string,ip_octets,netmask_octets,netmask)

    def toSubnetZeroed(self):
        subnet = ""
        count = 0
        for octet in self.netmask:
            count += countBits(int(octet))
        for octet in range(len(self.IP)-1):
            subnet += (str(int(self.IP[octet]) & int(self.netmask[octet]))) + '.'
        subnet += str(int(self.IP[len(self.IP)-1]) & int(self.netmask[len(self.netmask)-1]))
        subnet += '/' + str(count)
        return subnet

    def toSubnet(self):
        subnet = ""
        count = 0
        for octet in self.netmask:
            count += countBits(int(octet))
        for octet in range(len(self.IP)-1):
            subnet += str(self.IP[octet]) + '.'
        subnet += str(self.IP[len(self.IP)-1])
        subnet += '/' + str(count)
        return subnet

