#!/usr/bin/python3


from asyncua import Client
from asyncua import ua
import yaml
import sys
import os.path
import logging
import asyncio





'''
TODO UA Sinumerik File Transfer:

1.  Check Endpoint, User, Password, Encryption
    Create Connection with Server
//2. Verify User and target
3. Create/Elevate internal User to SinuWriteAll or SinuReadAll
4. Read Methods Node, Check if TransferFileToServer/ReadFileFromServer exists
5. Translate Target Path
• Sinumerik/FileSystem/Part Program/partprg.mpf
• Sinumerik/FileSystem/Sub Program/subprg.spf
• Sinumerik/FileSystem/Work Pieces/wrkprg.wpf
• Sinumerik/FileSystem/NCExtend/Program.mpf
• Sinumerik/FileSystem/ExtendedDrives/USBdrive/Q3.mpf
6. Set Overwrite Tag
7. Check if Transfer Value is Byte-String (uft-8)
8. Call Method, Analyse Return value
'''


def global_init():
    init_logging()
    yamlHandler().prim_setup()



def init_logging():
    log_format = f"%(asctime)s [%(processName)s] [%(name)s] [%(levelname)s]  %(message)s"
    log_level = logging.DEBUG
    logging.basicConfig(
        level = log_level,
        format = log_format,
        handlers = [
            logging.FileHandler(filename='Debug.log',mode='w',encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )


#Create Class for ini Handling
class yamlHandler:

    def __init__(self):
        self.src_path = os.path.split((os.path.realpath(__file__)))[0] + r'\ua_config.yaml'


    def prim_setup(self):
        if not os.path.isfile(self.src_path):
            self.add('IP-address','192.168.214.241')
            self.add('user','auduser')
            self.add('password','Sunrise!1')
            self.add('port',4840)
            self.add('encryption',['None','128Bit','256Bit'])




    def read(self, key):
        self.key = key
        with open(self.src_path, 'r') as f:
            self.ret_val = yaml.safe_load(f)
            if self.ret_val is None:
                return False
            else:
                try:
                    return (self.ret_val[key])
                except KeyError:
                    print("Broken Key in Yaml File. Delete " + self.src_path + " and retry.")
                    exit()




    def add(self, key, value):
        assert key
        self.key = key
        self.value = value
        self.yaml_cont = {}
        if os.path.isfile(self.src_path):
            with open(self.src_path, 'r') as f:
                self.yaml_cont = yaml.safe_load(f) or {}
        self.yaml_cont[self.key] = self.value
        with open(self.src_path, 'w') as f:
            yaml.dump(self.yaml_cont, f)
            print(self.yaml_cont)



class OPCHandler:
    def __init__(self, endpoint,user,password,security=None,cert_path=None,private_key=None):
        self._endpoint = endpoint
        self.client = Client(endpoint)
        self.client.set_user(user)
        self.client.set_password(password)
        '''
        1. OPC UA Server "Zertifikate autom. akzeptieren" muss aktiv sein sonst Exception "BadSecurityChecksFailed"
        2. Wenn Security != None 
        security übersetzen in entsprechenden Aufruf aus asyncua.crypto.security_policies
        cert_path + key als raw string
        z.B.:
        cert = f"certificates/peer-certificate-example.der"
        private_key = f"certificates/peer-private-key-example.pem"
        '''
        if security is not None:
            self.client.set_security(security,cert_path,private_key)
        logging.debug("Init successfully for endpoint: %r",endpoint)
        return

    async def __aenter__(self):
        logging.debug("Trying to connect to endpoint: %r",self._endpoint)
        await self.client.connect()
        return self.client

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.disconnect()


async def transfer_file(endpoint,user,pw,path,filename,mode='r',content='',ovr=0):
    async with OPCHandler(endpoint,user,pw) as client:
        logging.debug("Namespace contains %r",await client.get_namespace_array())
        root_node = client.get_root_node()
        logging.info("Connection Successfully. Root Node is %r",root_node)

        '''
        #Find Methods node
        '''
        uri = 'SinumerikVarProvider'
        namespace = await client.get_namespace_index(uri)
        methods_node_id = ua.NodeId('/Methods',namespace)
        methods_node = client.get_node(methods_node_id)
        logging.debug("Methods node found %r",methods_node)

        '''
        #Create IDs for file and user handling
        '''
        getuserlist_id = ua.NodeId('/Methods/GetUserList',namespace)
        adduser_id = ua.NodeId('/Methods/AddUser',namespace)
        getmyaccessrights_id = ua.NodeId('/Methods/GetMyAccessRights', namespace)
        giveuseraccessrights_id = ua.NodeId('/Methods/GiveUserAccess', namespace)
        copyfiletoserver_id = ua.NodeId('/Methods/CopyFileToServer', namespace)
        copyfilefromserver_id = ua.NodeId('/Methods/CopyFileFromServer', namespace)

        '''
        #Get Nodes for File and User Handling
        '''
        getuserlist = client.get_node(getuserlist_id)
        adduser = client.get_node(adduser_id)
        getmyaccessrights = client.get_node(getmyaccessrights_id)
        giveuseraccessrights = client.get_node(giveuseraccessrights_id)
        copyfiletoserver = client.get_node(copyfiletoserver_id)
        copyfilefromserver = client.get_node(copyfilefromserver_id)

        '''
        #Set Rights for File Transfer
        '''
        usr_arg = ua.Variant()
        usr_arg.VariantType = ua.VariantType.String
        usr_arg.Value = user
        rights_arg = ua.Variant()
        rights_arg.VariantType = ua.VariantType.String
        rights_arg.Value = 'SinuWriteAll;SinuReadAll'



        try:
            await methods_node.call_method(giveuseraccessrights, usr_arg,rights_arg)
            logging.debug(f"Successfully given rights {rights_arg} to user {usr_arg}")
        except:
            logging.debug(f"Failed giving rights {rights_arg} to user {usr_arg}. System Exit!")
            sys.exit()

        '''
        #Build Path and Content Arguments
        • Sinumerik/FileSystem/Part Program/partprg.mpf
        • Sinumerik/FileSystem/Sub Program/subprg.spf
        • Sinumerik/FileSystem/Work Pieces/wrkprg.wpf
        • Sinumerik/FileSystem/NCExtend/Program.mpf
        • Sinumerik/FileSystem/ExtendedDrives/USBdrive/Q3.mpf
        '''
        arg_path = ua.Variant()
        arg_path.VariantType = ua.VariantType.String
        arg_path.Value = f"Sinumerik/FileSystem/{path}/{filename}"

        arg_content = ua.Variant()
        arg_content.VariantType = ua.VariantType.ByteString
        byte_string = bytes(content,'utf-8')
        arg_content.Value = byte_string

        arg_overwrite = ua.Variant()
        arg_overwrite.VariantType = ua.VariantType.Boolean
        arg_overwrite.Value = ovr

        if mode == 'r':
            logging.debug(f"Reading File {arg_path.Value} from server")
            content = await methods_node.call_method(copyfilefromserver,arg_path)
        elif mode == 'w':
            print(arg_content.Value)
            logging.debug(f"Writing to File {arg_path.Value} from server")
            content = await methods_node.call_method(copyfiletoserver,arg_path,arg_content,arg_overwrite)
        else:
            content = 0
        logging.debug(f"Return value is: {content}")
        return content





if __name__ == "__main__":
    global_init()
    endpoint = 'opc.tcp://192.168.214.241:4840'
    user = 'auduser'
    password = 'Sunrise!1'
    path = 'Part Program'
    filename = 'TEST_RR.mpf'
    mode = 'w'
    content = 'Hallo Welt'
    ovr = 1
    val = asyncio.run(transfer_file(endpoint,user,password,path,filename,mode,content,ovr))
    logging.debug(f"Return value is {val.decode('utf-8')}")
