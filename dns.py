
import socket, glob, json
import struct




# adding a listiner to MDNS port 5353

ip = '224.0.0.251'
port = 5353

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)

sock.bind(('', port))
mreq = struct.pack('4sl', socket.inet_aton(ip),socket.INADDR_ANY)

sock.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP,mreq)




def buildresponce(data):

    # transacrion id
    TransactionID = data[:2]

    # flaga 
    Flags = getflags(data[2:4])
    
    # question count 
    QDCOUNT = b'\x00\x01'

    # Answer count

    ACOUNT = len(getrecs(data[12:])[0]).to_bytes(2, byteorder='big')

    #Nameserver count 

    NSCOUNT = (0).to_bytes(2,byteorder='big')

    # Add count 
    
    ARCOUNT = (0).to_bytes(2,byteorder='big')
    

    # DNS Header
    dnsheader = TransactionID+Flags+QDCOUNT+ACOUNT+NSCOUNT+ARCOUNT


    records, rectype, domainname = getrecs(data[12:])
    
     # DNS questions
    dnsquestion = buildquestion(domainname, rectype)


    # DNS Body 
    dnsbody = b''


    for record in records:
        dnsbody += rectobytes(domainname,rectype, record["ttl"],record['value'])
    
    return dnsheader + dnsquestion + dnsbody



# add loop to listen to queryies and buld a response

while 1:
   data, addr = sock.recvfrom(512)
   r = buildresponce(data)
   sock.sendto(r, addr)

# lood zone data
def loadzone():
    zonefiles = glob.glob('domains/*.json')
    jsonzone = {}
    for zone in zonefiles:
        with open (zone) as zonedata:
            data = json.load(zonedata)  
            zonename = data['name']
            jsonzone[zonename] = data
        
    return jsonzone
            
            



zonedata = loadzone()



def getzone(domain):
    global zonedata

    zone_name = '.'.join(domain)
    try:
        return zonedata[zone_name]
    except:
        return {}

# get flags from data
def getflags(flags):

    byte1 = bytes(flags[:1])
    byte2 = bytes(flags[1:2])
    
    rflags = ''
    
    QR = '1'

    OPCODE = ''
    for bit in range(1,5):
        OPCODE += str(ord(byte1)&(1<<bit))
    
    AA = '1'
    TC = '0'
    RD = '0'

    RA = '0'
    Z = '000'
    RCODE = '0000'

    return int(QR+OPCODE+AA+TC+RD, 2).to_bytes(1,byteorder='big')+int(RA + Z+RCODE, 2).to_bytes(1,byteorder='big')

    
def getquestiondomain(data):
    
    state = 0 
    expectedlength = 0
    domainstring =''
    domainparts = []

    x = 0
    y = 0

    for byte in data:
        if state == 1:
            domainstring += chr(byte)
            x += 1
             
            if x == expectedlength:
                domainparts.append(domainstring)
                domainstring = ''
                state = 0
                x = 0    
            if byte == 0:
                break
        else:
            state = 1
            expectedlength = byte
        y +=1 

    questiontype = data[y:y+2]
    return (domainparts, questiontype)


def  getrecs(data):
    domain, questiontype = getquestiondomain(data)

    qt = ''
    if questiontype == b'\x00\x01':
        qt = 'a'

    zone = getzone(domain)

    return (zone[qt], qt, domain)


def buildquestion(domain, rectype):
    qbyte = b''

    for part in domain:
        length = len(part)
        qbyte += bytes([length])

        for char in part:
            qbyte += ord(char).to_bytes(1, byteorder='big')
        

    qbyte += (0).to_bytes(1,byteorder='big')
    if rectype == 'a':
        qbyte += (1).to_bytes(2,byteorder='big')
    qbyte += (1).to_bytes(2,byteorder='big')
    return qbyte


def rectobytes(domainname, recttype, recttl, recvalue):
    rbytes = b'\xc0\x0c'

    if recttype == 'a':
        rbytes = rbytes + bytes([0]) + bytes([1])
    
    rbytes = rbytes + bytes([0]) + bytes([1])

    rbytes += int(recttl).to_bytes(4,byteorder='big')

    if recttype == 'a':
        rbytes = rbytes + bytes([0]) + bytes([4])

        for part in recvalue.split('.'):
            rbytes += bytes([int(part)])

    return rbytes








