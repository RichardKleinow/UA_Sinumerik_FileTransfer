#!/usr/bin/python3
from typing import Optional

from asyncua import Client
from asyncua import ua
import yaml
import os.path
import logging
import asyncio

logging.basicConfig(filename='Debug.log', encoding='utf-8')
logging.basicConfig(level=logging.INFO)


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
    yamlHandler().prim_setup()



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
        self.client.connect()
        return self.client

    def __enter__(self):
        self.client.connect()
        return self.client

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.client.disconnect()



def transfer_file():
        try:
            client = OPCHandler('opc.tcp://192.168.214.241:4840','auduser','Sunrise!1')
            Client.fin
        except:
            logging.ERROR("Unable to Connect to Endpoint.")



        file_node = client.get_node("ns=2;s=/Methods")
        #1. user auslesen und verifizieren
        #2. user entsprechende Berechtigung erteilen
        #3. Methoden Knoten auslesen
        #4. Entsprechende Methode finden und merken
        #5. Input/Output Argumente erstellen
        # File Transfer -> Text muss als Byte-String (encode('utf8')) vorliegen
        # File lesen -> Text aus Byte-String decodiert und gespeichert werden
        # Argutmente und Datentypen lassen sich mit UAExpert ermitteln
        #6. Methode aufrufen
        #7. WIN

        methods = await file_node.get_methods()
        print(methods)
        GiveUserAccess = methods[9]
        GetUserList = methods[8]
        GetMyAccessRights = methods[6]
        CopyFileFromServer = methods[2]
        CopyFileToServer = methods[3]

        usr_arg = ua.Variant()
        usr_arg.VariantType = ua.VariantType.String
        usr_arg.Value = "auduser"
        right_arg = ua.Variant()
        right_arg.VariantType = ua.VariantType.String
        right_arg.Value = "SinuWriteAll"
        #right_arg.Value = "SinuReadAll"
        await file_node.call_method(GiveUserAccess, usr_arg,right_arg)




        arg_path = ua.Variant()
        arg_path.VariantType = ua.VariantType.String
        arg_path.Value = "Sinumerik/FileSystem/Part Program/KREIS_XZ.mpf"
        arg = await file_node.call_method(CopyFileFromServer,arg_path)
        print("")
        print("--Programm lesen--")
        print("KREIS_XZ.mpf")
        print(str(arg,'utf-8'))



        arg_path.Value = "Sinumerik/FileSystem/Part Program/TEST_RR.mpf"
        arg_string = ua.Variant()
        arg_string.VariantType = ua.VariantType.ByteString
        arg_string.Value = "TEST String OVERWRITE".encode('utf-8')
        arg_overwrite = ua.Variant()
        arg_overwrite.VariantType = ua.VariantType.Boolean
        arg_overwrite.Value = False
        ret =await file_node.call_method(CopyFileToServer,arg_path,arg_string,arg_overwrite)
        print(ret)




if __name__ == "__main__":
    global_init()
    transfer_file()

